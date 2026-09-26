"""Detect systemd timers that have silently stopped firing.

Linux / systemd only (``systemctl`` and ``systemd-analyze``). Runs locally by default, or against
another machine with ``--host`` over ``ssh -o BatchMode=yes``. Prefer running it from a DIFFERENT
machine than the one it watches: a checker on the watched host shares the failure domain it
exists to report.

Three rules make it honest:

* **Cadence comes from the declaration.** The expected period is derived from the timer's own
  ``OnCalendar=`` / ``OnUnitActiveSec=`` (read with ``systemctl cat``, resolved with
  ``systemd-analyze``), never from the observed NextElapse/LastTrigger pair: an ancient
  LastTrigger would enlarge an observed cadence and exonerate the outage.
* **An empty LastTrigger has three meanings, kept apart.** Not yet due (fine), timer unit not
  active (a definite state, reported but not paged), or genuinely unreadable (UNKNOWN).
* **"Overdue" is confirmed against the declared calendar evaluated FROM LastTrigger.** A timer
  that fires every minute during weekday business hours is not overdue at night or on Sunday;
  its next declared elapse after the last trigger is still in the future.

Exit status: 0 OK, 1 FINDINGS, 3 UNKNOWN.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
import time
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path

from ._state import StateCorrupt, load_json_state, save_json_state
from .alerts import alert
from .exitcodes import EXIT_FINDINGS, EXIT_OK, EXIT_UNKNOWN

DEFAULT_STATE_FILE = "~/.local/state/honest-watchdogs/systemd-timer-liveness.json"
DEFAULT_TIMEOUT = 120.0
DEFAULT_CADENCE_MULTIPLIER = 2.0
# Short timers commonly have AccuracySec/RandomizedDelaySec and transient job overlap. Five
# minutes keeps a one-minute timer from flapping while still detecting a stall promptly.
DEFAULT_MINIMUM_OVERDUE_SECONDS = 300.0
DEFAULT_REMINDER_SECONDS = 21600.0
# Each systemd-analyze call asks for three iterations. Chaining four calls yields twelve
# consecutive declared elapses, enough to expose weekly long gaps such as a Mon..Fri weekend.
CALENDAR_RESOLUTION_ROUNDS = 4

LIST_COMMAND = "systemctl list-timers --all --no-pager --no-legend"
TRIGGER_KEYS = ("OnCalendar", "OnUnitActiveSec", "OnBootSec", "OnActiveSec")
SLACK_KEYS = ("RandomizedDelaySec", "AccuracySec")
SCHEDULE_KEYS = (*TRIGGER_KEYS, *SLACK_KEYS)

_CAT_BEGIN = "__HW_TIMER_CAT_BEGIN__="
_CAT_END = "__HW_TIMER_CAT_END__="
_RESOLVE_BEGIN = "__HW_TIMER_RESOLVE_BEGIN__="
_RESOLVE_END = "__HW_TIMER_RESOLVE_END__="


def run_remote(host: str | None, command: str, timeout: float) -> tuple[int, str, str]:
    """Run one shell command locally (``host=None``) or over ssh.

    Transport failure is returned as a non-zero rc with a reason, never as empty success.
    """

    argv = (
        ["sh", "-c", command]
        if host is None
        else ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host, command]
    )
    where = host or "localhost"
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return -1, "", f"command on {where} timed out after {timeout}s"
    except Exception as exc:  # any launch failure is UNKNOWN, never OK
        return -1, "", f"could not run command on {where}: {exc}"
    return proc.returncode, proc.stdout, proc.stderr


def _where(host: str | None) -> str:
    return host or "localhost"


def parse_timer_list(stdout: str) -> list[str]:
    """Extract UNIT from list-timers' variable-width human table.

    NEXT, LEFT, LAST and PASSED all contain variable numbers of words. UNIT and ACTIVATES are
    the final two whitespace-delimited columns, including in the ``n/a`` form, so parsing from
    the right is stable.
    """

    timers: list[str] = []
    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        unit = fields[-2]
        if unit.endswith(".timer"):
            timers.append(unit)
    return list(dict.fromkeys(timers))


def _shell(value: str) -> str:
    return shlex.quote(value)


def build_cat_command(timer_ids: list[str]) -> str:
    """One framed command that cats every enumerated timer, preserving each rc."""

    quoted = " ".join(shlex.quote(unit) for unit in timer_ids)
    return (
        f"for unit in {quoted}; do "
        f"printf '%s%s\\n' {_shell(_CAT_BEGIN)} \"$unit\"; "
        'systemctl cat -- "$unit" 2>&1; hw_cat_rc=$?; '
        f"printf '%s%s\\n' {_shell(_CAT_END)} \"$hw_cat_rc\"; "
        "done"
    )


def parse_cat_batch(stdout: str) -> dict[str, dict]:
    records: dict[str, dict] = {}
    unit: str | None = None
    body: list[str] = []
    for line in stdout.splitlines():
        if line.startswith(_CAT_BEGIN):
            unit = line[len(_CAT_BEGIN):]
            body = []
        elif line.startswith(_CAT_END) and unit is not None:
            try:
                rc = int(line[len(_CAT_END):])
            except ValueError:
                rc = -1
            records[unit] = {"rc": rc, "text": "\n".join(body)}
            unit = None
            body = []
        elif unit is not None:
            body.append(line)
    return records


def _logical_lines(text: str) -> list[str]:
    """Join systemd-style backslash continuations before parsing assignments."""

    result: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = pending + raw.lstrip() if pending else raw
        if line.endswith("\\"):
            pending = line[:-1] + " "
            continue
        result.append(line)
        pending = ""
    if pending:
        result.append(pending)
    return result


def parse_declared_schedule(text: str) -> dict[str, list[str]]:
    """Parse the effective timer declaration from ``systemctl cat`` output.

    An empty assignment to any trigger resets the whole trigger list, per systemd.timer
    semantics. This matters for the common drop-in shape ``OnCalendar=daily`` in the unit, then
    ``OnCalendar=`` and ``OnCalendar=hourly`` in an override: the effective schedule is hourly.
    """

    schedule: dict[str, list[str]] = {key: [] for key in SCHEDULE_KEYS}
    section = ""
    for raw in _logical_lines(text):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if section != "Timer" or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in schedule:
            continue
        value = value.strip()
        if not value and key in TRIGGER_KEYS:
            for name in TRIGGER_KEYS:
                schedule[name] = []
        elif not value:
            schedule[key] = []
        elif key in SLACK_KEYS:
            schedule[key] = [value]  # scalar: a later drop-in replaces it
        else:
            schedule[key].append(value)
    return schedule


def build_show_command(timer_ids: list[str]) -> str:
    ids = " ".join(shlex.quote(unit) for unit in timer_ids)
    return (
        "LC_ALL=C TZ=UTC systemctl show -p Id -p LastTriggerUSec "
        f"-p ActiveState -p ActiveEnterTimestamp -- {ids}"
    )


def parse_show(stdout: str) -> dict[str, dict[str, str]]:
    """Return the whole property block per unit, not just LastTriggerUSec.

    An empty LastTriggerUSec has THREE meanings, and collapsing them into one verdict is the
    defect this parser exists to avoid: the timer has not reached its first elapse yet (fine),
    the timer unit is not active at all (a definite state), or we genuinely could not read it.
    ActiveState and ActiveEnterTimestamp are what tell them apart.
    """

    observed: dict[str, dict[str, str]] = {}
    block: dict[str, str] = {}
    for line in [*stdout.splitlines(), ""]:
        if not line.strip():
            if block.get("Id"):
                observed[block["Id"]] = dict(block)
            block = {}
            continue
        key, separator, value = line.partition("=")
        if separator:
            block[key] = value
    return observed


def build_resolve_command(
    expressions: list[tuple[str, str]],
    calendar_base_times: list[float | None] | None = None,
) -> str:
    """Build framed resolver calls, preserving each process's real exit code.

    systemd-analyze is never piped: a pipe masks its rejection exit code. Its failure text is
    also retained and checked as a second guard.
    """

    commands: list[str] = []
    for index, (kind, value) in enumerate(expressions):
        base_option = ""
        if calendar_base_times and calendar_base_times[index] is not None:
            base_option = f"--base-time=@{int(calendar_base_times[index])} "
        commands.append(
            f"printf '%s%s\\n' {_shell(_RESOLVE_BEGIN)} {_shell(str(index))}; "
            f"LC_ALL=C TZ=UTC systemd-analyze {kind} "
            + ("--iterations=3 " if kind == "calendar" else "")
            + base_option
            + f"-- {_shell(value)} 2>&1; hw_resolve_rc=$?; "
            f"printf '%s%s:%s\\n' {_shell(_RESOLVE_END)} "
            f'{_shell(str(index))} "$hw_resolve_rc"'
        )
    return "; ".join(commands)


def parse_resolve_batch(stdout: str) -> dict[int, dict]:
    records: dict[int, dict] = {}
    index: int | None = None
    body: list[str] = []
    for line in stdout.splitlines():
        if line.startswith(_RESOLVE_BEGIN):
            try:
                index = int(line[len(_RESOLVE_BEGIN):])
            except ValueError:
                index = None
            body = []
        elif line.startswith(_RESOLVE_END) and index is not None:
            end_index, separator, rc_text = line[len(_RESOLVE_END):].partition(":")
            try:
                rc = int(rc_text) if separator and int(end_index) == index else -1
            except ValueError:
                rc = -1
            records[index] = {"rc": rc, "output": "\n".join(body)}
            index = None
            body = []
        elif index is not None:
            body.append(line)
    return records


_CALENDAR_STAMP = re.compile(
    r"^\s*(?:Next elapse|Iteration #\d+):\s+\w{3}\s+"
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? UTC\s*$"
)


def calendar_stamps(output: str) -> list[float]:
    return sorted(
        {
            datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC).timestamp()
            for line in output.splitlines()
            if (match := _CALENDAR_STAMP.match(line))
        }
    )


def calendar_cadence(output: str) -> float | None:
    stamps = calendar_stamps(output)
    if len(stamps) < 2:
        return None
    intervals = [later - earlier for earlier, later in pairwise(stamps)]
    if not intervals or any(interval <= 0 for interval in intervals):
        return None
    # Irregular calendars (the first Sunday of each month) have 28- and 35-day gaps. The longest
    # declared gap avoids calling a healthy timer overdue during its legitimate long interval.
    return max(intervals)


def timespan_seconds(output: str) -> float | None:
    for line in output.splitlines():
        match = re.match(r"^\s*us:\s*(\d+)\s*$", line)
        if match:
            return int(match.group(1)) / 1_000_000
    return None


def parse_last_trigger(value: str) -> float | None:
    match = re.match(r"^\w{3} (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? UTC$", value.strip())
    if not match:
        return None
    return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC).timestamp()


def derive_cadence(
    schedule: dict[str, list[str]],
    resolved: dict[tuple[str, str], dict],
) -> tuple[float | None, str]:
    candidates: list[float] = []
    errors: list[str] = []

    for spec in schedule["OnCalendar"]:
        record = resolved.get(("calendar", spec))
        if not record:
            errors.append(f"OnCalendar={spec!r} was not resolved")
            continue
        output = record["output"]
        cadence = calendar_cadence(output)
        if record["rc"] != 0 or "Failed to parse calendar specification" in output or cadence is None:
            errors.append(f"cannot resolve OnCalendar={spec!r}: {output.strip()[:160]}")
        else:
            candidates.append(cadence)

    for span in schedule["OnUnitActiveSec"]:
        record = resolved.get(("timespan", span))
        if not record:
            errors.append(f"OnUnitActiveSec={span!r} was not resolved")
            continue
        seconds = timespan_seconds(record["output"])
        if (
            record["rc"] != 0
            or "Failed to parse time span" in record["output"]
            or seconds is None
            or seconds <= 0
        ):
            errors.append(
                f"cannot resolve OnUnitActiveSec={span!r}: {record['output'].strip()[:160]}"
            )
        else:
            candidates.append(seconds)

    if errors:
        return None, "; ".join(errors)
    if candidates:
        return min(candidates), ""
    one_shot = [f"{key}={value}" for key in ("OnBootSec", "OnActiveSec") for value in schedule[key]]
    if one_shot:
        return None, "only one-shot schedule declarations are present: " + ", ".join(one_shot)
    return None, "no recurring declared schedule was found"


def derive_declared_slack(
    schedule: dict[str, list[str]],
    resolved: dict[tuple[str, str], dict],
) -> tuple[float | None, str]:
    """Declared jitter/accuracy that may legitimately delay a trigger."""

    total = 0.0
    for key in SLACK_KEYS:
        for span in schedule[key]:
            record = resolved.get(("timespan", span))
            if not record:
                return None, f"{key}={span!r} was not resolved"
            seconds = timespan_seconds(record["output"])
            if record["rc"] != 0 or "Failed to parse time span" in record["output"] or seconds is None:
                return None, f"cannot resolve {key}={span!r}: {record['output'].strip()[:160]}"
            total += seconds
    return total, ""


def _unknown(host: str | None, stage: str, reason: str, *, rc: int | None = None) -> tuple[str, str, dict]:
    facts: dict = {"host": _where(host), "stage": stage, "findings": [], "unknowns": []}
    if rc is not None:
        facts["transport_rc"] = rc
    return "unknown", reason, facts


def confirm_overdue_against_declared_calendar(
    host: str | None,
    timeout: float,
    now: float,
    candidates: list[dict],
    cadence_multiplier: float,
    minimum_overdue_seconds: float,
) -> list[dict]:
    """Drop overdue candidates whose declared calendar has not come due since they last fired.

    Cadence alone cannot tell a stalled timer from a WINDOWED one. A timer declared
    ``Mon..Fri *-*-* 12..21:*:00`` has a 60-second cadence, so at 22:05 the cadence arithmetic
    calls it overdue. It is not: its next declared elapse after its last trigger is 12:00 the
    next weekday. Without this step it pages every night and all weekend, and a watch that pages
    on a job doing its job gets muted.

    The due time comes from the DECLARED calendar evaluated from LastTrigger, never from
    systemd's NextElapse. An ancient LastTrigger gives an ancient due time, so a real outage
    still fires. Any resolution failure keeps the finding: this step can only remove a false
    alarm, never hide a real one.
    """

    expressions: list[tuple[str, str]] = []
    bases: list[float | None] = []
    owners: list[int] = []
    for position, candidate in enumerate(candidates):
        schedule = candidate["schedule"]
        if schedule["OnUnitActiveSec"] or not schedule["OnCalendar"]:
            continue
        for spec in schedule["OnCalendar"]:
            expressions.append(("calendar", spec))
            bases.append(candidate["last_trigger_epoch"])
            owners.append(position)
    if not expressions:
        return candidates
    rc, stdout, _stderr = run_remote(host, build_resolve_command(expressions, bases), timeout)
    if rc != 0:
        return candidates
    records = parse_resolve_batch(stdout)
    due: dict[int, float] = {}
    unresolved: set[int] = set()
    for index, position in enumerate(owners):
        record = records.get(index)
        stamps = calendar_stamps(record["output"]) if record and record["rc"] == 0 else []
        if not stamps:
            unresolved.add(position)
            continue
        due[position] = min(due.get(position, stamps[0]), stamps[0])
    confirmed: list[dict] = []
    for position, candidate in enumerate(candidates):
        if position not in due or position in unresolved:
            confirmed.append(candidate)
            continue
        cadence = candidate["cadence_seconds"]
        grace = (
            max(minimum_overdue_seconds, (cadence_multiplier - 1) * cadence)
            + candidate["declared_slack_seconds"]
        )
        candidate["declared_due_epoch"] = due[position]
        if now - due[position] > grace:
            confirmed.append(candidate)
    return confirmed


def probe(
    host: str | None,
    timeout: float,
    now: float,
    cadence_multiplier: float,
    minimum_overdue_seconds: float,
) -> tuple[str, str, dict]:
    """Sweep every timer and return ``(ok|findings|unknown, reason, facts)``."""

    where = _where(host)
    rc, stdout, stderr = run_remote(host, LIST_COMMAND, timeout)
    if rc != 0:
        return _unknown(host, "list-timers",
                        f"enumerating timers on {where} failed (rc={rc}): {stderr.strip()[:200]}",
                        rc=rc)
    timer_ids = parse_timer_list(stdout)
    if not timer_ids:
        return _unknown(host, "list-timers",
                        f"systemctl on {where} enumerated zero timers; cannot measure")

    rc, cat_out, cat_err = run_remote(host, build_cat_command(timer_ids), timeout)
    if rc != 0:
        return _unknown(host, "systemctl-cat",
                        f"reading timer declarations on {where} failed (rc={rc}): "
                        f"{cat_err.strip()[:200]}", rc=rc)
    cats = parse_cat_batch(cat_out)

    rc, show_out, show_err = run_remote(host, build_show_command(timer_ids), timeout)
    if rc != 0:
        return _unknown(host, "systemctl-show",
                        f"reading LastTriggerUSec on {where} failed (rc={rc}): "
                        f"{show_err.strip()[:200]}", rc=rc)
    triggers = parse_show(show_out)

    schedules: dict[str, dict[str, list[str]]] = {}
    unknowns: list[dict] = []
    inactive: list[dict] = []
    expressions: list[tuple[str, str]] = []
    for unit in timer_ids:
        record = cats.get(unit)
        if not record or record["rc"] != 0:
            detail = record["text"].strip()[:160] if record else "no framed output"
            unknowns.append({"kind": "unknown", "unit": unit, "reason": f"systemctl cat failed: {detail}"})
            continue
        schedule = parse_declared_schedule(record["text"])
        schedules[unit] = schedule
        expressions.extend(("calendar", value) for value in schedule["OnCalendar"])
        for key in ("OnUnitActiveSec", *SLACK_KEYS):
            expressions.extend(("timespan", value) for value in schedule[key])

    expressions = list(dict.fromkeys(expressions))
    resolved: dict[tuple[str, str], dict] = {}
    if expressions:
        rc, resolve_out, resolve_err = run_remote(host, build_resolve_command(expressions), timeout)
        if rc != 0:
            return _unknown(host, "systemd-analyze",
                            f"resolving declared schedules on {where} failed (rc={rc}): "
                            f"{resolve_err.strip()[:200]}", rc=rc)
        records = parse_resolve_batch(resolve_out)
        resolved = {expr: records[i] for i, expr in enumerate(expressions) if i in records}

        # Three future elapses can alias an irregular schedule: on a Sunday, Mon..Fri yields
        # Mon/Tue/Wed and hides the weekend gap. Continue from the last resolved elapse, still
        # using direct --iterations=3 processes whose individual rc and output are retained.
        calendar_expressions = [e for e in expressions if e[0] == "calendar"]
        for _round in range(1, CALENDAR_RESOLUTION_ROUNDS):
            round_expressions: list[tuple[str, str]] = []
            round_bases: list[float | None] = []
            prior_maxima: dict[tuple[str, str], float] = {}
            for expression in calendar_expressions:
                record = resolved.get(expression)
                stamps = calendar_stamps(record["output"]) if record else []
                if not stamps or record["rc"] != 0:
                    continue
                round_expressions.append(expression)
                round_bases.append(stamps[-1] + 1)  # the next elapse is strictly after this
                prior_maxima[expression] = stamps[-1]
            if not round_expressions:
                break
            rc, round_out, round_err = run_remote(
                host, build_resolve_command(round_expressions, round_bases), timeout
            )
            if rc != 0:
                return _unknown(host, "systemd-analyze",
                                f"extending declared calendars on {where} failed (rc={rc}): "
                                f"{round_err.strip()[:200]}", rc=rc)
            round_records = parse_resolve_batch(round_out)
            advanced = False
            for index, expression in enumerate(round_expressions):
                record = round_records.get(index)
                if not record:
                    resolved[expression]["rc"] = -1
                    continue
                resolved[expression]["output"] += "\n" + record["output"]
                if record["rc"] != 0:
                    resolved[expression]["rc"] = record["rc"]
                new_stamps = calendar_stamps(record["output"])
                if new_stamps and new_stamps[-1] > prior_maxima[expression]:
                    advanced = True
            if not advanced:
                break

    findings: list[dict] = []
    overdue_candidates: list[dict] = []
    timers: list[dict] = []
    already_unknown = {item["unit"] for item in unknowns}
    for unit in timer_ids:
        if unit in already_unknown:
            continue
        schedule = schedules[unit]
        cadence, cadence_error = derive_cadence(schedule, resolved)
        if cadence is None:
            unknowns.append({"kind": "unknown", "unit": unit, "reason": cadence_error, "schedule": schedule})
            continue
        declared_slack, slack_error = derive_declared_slack(schedule, resolved)
        if declared_slack is None:
            unknowns.append({"kind": "unknown", "unit": unit, "reason": slack_error, "schedule": schedule})
            continue
        if unit not in triggers:
            unknowns.append({"kind": "unknown", "unit": unit, "schedule": schedule,
                             "reason": "unit vanished between list-timers and systemctl show"})
            continue
        props = triggers[unit]
        raw_trigger = props.get("LastTriggerUSec", "")
        last_trigger = parse_last_trigger(raw_trigger)
        threshold = max(cadence_multiplier * cadence, minimum_overdue_seconds) + declared_slack
        if last_trigger is None:
            # THE THREE-WAY SPLIT. Reporting all of these as "cannot measure" makes a brand-new
            # healthy timer look like an instrument failure, and at a five-minute schedule that
            # is a warning every five minutes forever. It gets muted, and a muted detector is
            # worse than the blind spot it closed.
            active_state = props.get("ActiveState", "")
            if not active_state:
                unknowns.append({"kind": "unknown", "unit": unit, "schedule": schedule,
                                 "reason": f"LastTriggerUSec is unavailable: {raw_trigger!r}"})
                continue
            if active_state != "active":
                # A definite state, not an absence of measurement. An enabled-but-inactive timer
                # will never fire: worth SAYING, not worth paging every five minutes. Timers
                # are legitimately inactive when, for example, the hardware they probe is absent.
                inactive.append({"kind": "inactive", "unit": unit,
                                 "active_state": active_state, "schedule": schedule})
                continue
            activated = parse_last_trigger(props.get("ActiveEnterTimestamp", ""))
            if activated is None:
                unknowns.append({
                    "kind": "unknown", "unit": unit, "schedule": schedule,
                    "reason": "timer is active and has never fired, and ActiveEnterTimestamp is "
                              f"unreadable: {props.get('ActiveEnterTimestamp', '')!r}",
                })
                continue
            since_activation = now - activated
            row = {
                "unit": unit, "cadence_seconds": cadence, "declared_slack_seconds": declared_slack,
                "last_trigger_epoch": None, "age_seconds": since_activation,
                "threshold_seconds": threshold, "never_fired": True,
                "active_enter_epoch": activated, "schedule": schedule,
            }
            timers.append(row)
            if since_activation > threshold:
                # Active, past due, and never once fired. Reporting this as "cannot measure"
                # would exonerate it.
                findings.append({"kind": "never_fired", **row})
            continue
        age = now - last_trigger
        row = {
            "unit": unit, "cadence_seconds": cadence, "declared_slack_seconds": declared_slack,
            "last_trigger_epoch": last_trigger, "age_seconds": age,
            "threshold_seconds": threshold, "schedule": schedule,
        }
        timers.append(row)
        if age > threshold:
            overdue_candidates.append({"kind": "overdue", **row})

    findings.extend(
        confirm_overdue_against_declared_calendar(
            host, timeout, now, overdue_candidates, cadence_multiplier, minimum_overdue_seconds
        )
    )

    for bucket in (findings, unknowns, timers, inactive):
        bucket.sort(key=lambda item: item["unit"])
    facts = {
        "host": where,
        "enumerated": len(timer_ids),
        "timers": timers,
        "findings": findings,
        "unknowns": unknowns,
        "inactive": inactive,
        "cadence_multiplier": cadence_multiplier,
        "minimum_overdue_seconds": minimum_overdue_seconds,
    }
    if unknowns:
        return "unknown", f"{len(unknowns)} timer(s) could not be measured", facts
    if findings:
        return "findings", f"{len(findings)} timer(s) are overdue", facts
    if inactive:
        # Not a finding and not a page, but never a silent zero either.
        return "ok", f"{len(inactive)} timer(s) enabled but inactive", facts
    return "ok", "", facts


def load_state(path: Path) -> dict:
    """Load the latch record. Raises StateCorrupt rather than silently resetting it."""

    state = load_json_state(path)
    alerted = state.get("alerted", {})
    if not isinstance(alerted, dict) or not all(
        isinstance(v, (int, float)) and not isinstance(v, bool) for v in alerted.values()
    ):
        raise StateCorrupt(f"state file {path} has an invalid 'alerted' mapping")
    return state


def save_state(path: Path, state: dict) -> None:
    save_json_state(path, state)


def dedupe_key_for(host: str, kind: str, unit: str) -> str:
    """The host is load-bearing: identical unit names exist on different machines."""

    return f"systemd-timer-liveness/{kind}/{host}/{unit}"


def deliver_alerts(
    host: str,
    issues: list[dict],
    prev_alerted: dict[str, float],
    now: float,
    reminder_seconds: float,
) -> dict[str, float]:
    """Alert on each issue at most once per reminder interval; latch only on success."""

    alerted = dict(prev_alerted)
    for issue in issues:
        kind = issue["kind"]
        unit = issue["unit"]
        key = dedupe_key_for(host, kind, unit)
        last = alerted.get(key)
        if last is not None and now - last < reminder_seconds:
            continue
        if kind in ("overdue", "never_fired"):
            summary = (
                f"timer {unit} on {host} is {'overdue' if kind == 'overdue' else 'past due and has never fired'}: "
                f"age {issue['age_seconds']:.0f}s, threshold {issue['threshold_seconds']:.0f}s"
            )
            severity = "critical"
        else:
            summary = f"CANNOT MEASURE timer {unit} on {host}: {issue['reason']}"
            severity = "warn"
        result = alert(
            severity,
            "systemd-timer-liveness",
            summary,
            details={"host": host, **issue},
            dedupe_key=key,
            tags=("systemd", "timer-liveness"),
        )
        if result is not None and not result.success:
            continue  # stays due next run
        alerted[key] = now
    return alerted


def _emit(verdict: str, reason: str, facts: dict, json_mode: bool) -> None:
    payload = {"status": verdict.upper(), "reason": reason, **facts}
    if json_mode:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if verdict == "ok":
        # An OK line that omits the inactive count is a silent zero.
        extra = ""
        if facts.get("inactive"):
            names = ", ".join(item["unit"] for item in facts["inactive"])
            extra = f"; {len(facts['inactive'])} enabled but inactive: {names}"
        print(f"OK: {facts['host']} swept, {facts['enumerated']} timers are live{extra}")
    elif verdict == "findings":
        names = ", ".join(item["unit"] for item in facts["findings"])
        print(f"FINDINGS: {reason}: {names} | {json.dumps(payload, sort_keys=True)}")
    else:
        print(f"UNKNOWN: {reason} | {json.dumps(payload, sort_keys=True)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="systemd-timer-liveness",
        description="Detect systemd timers that have silently stopped firing. "
        "Exit 0 OK, 1 FINDINGS, 3 UNKNOWN.",
    )
    parser.add_argument(
        "--host", default=None,
        help="ssh destination to check (default: this machine). Prefer checking from a "
        "different machine than the one being watched.",
    )
    parser.add_argument("--state-file", default=DEFAULT_STATE_FILE)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--cadence-multiplier", type=float, default=DEFAULT_CADENCE_MULTIPLIER)
    parser.add_argument("--minimum-overdue-seconds", type=float,
                        default=DEFAULT_MINIMUM_OVERDUE_SECONDS)
    parser.add_argument("--reminder-seconds", type=float, default=DEFAULT_REMINDER_SECONDS)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="send no alerts and write no state")
    args = parser.parse_args(argv)
    if args.cadence_multiplier <= 0:
        parser.error("--cadence-multiplier must be greater than zero")
    if args.minimum_overdue_seconds < 0:
        parser.error("--minimum-overdue-seconds must not be negative")

    now = time.time()
    verdict, reason, facts = probe(
        args.host, args.timeout, now, args.cadence_multiplier, args.minimum_overdue_seconds
    )
    host = _where(args.host)

    state_error: str | None = None
    if not args.dry_run:
        state_path = Path(args.state_file).expanduser()
        try:
            previous = load_state(state_path).get("alerted", {})
        except StateCorrupt as exc:
            # Alert anyway, unlatched, and leave the file untouched: exit 3 below.
            state_error = str(exc)
            previous = {}
        issues = [*facts.get("findings", []), *facts.get("unknowns", [])]
        if verdict == "unknown" and not issues:
            issues = [{"kind": "unknown", "unit": "sweep", "reason": reason}]
        alerted = deliver_alerts(host, issues, previous, now, args.reminder_seconds)
        current_keys = {dedupe_key_for(host, i["kind"], i["unit"]) for i in issues}
        unknown_units = {i["unit"] for i in facts.get("unknowns", [])}
        current_keys.update(
            key for key in previous if any(key.endswith(f"/{unit}") for unit in unknown_units)
        )
        if "enumerated" not in facts:
            # A transport or stage failure observed no recoveries. Preserve existing latches so
            # one ssh blip cannot bypass the reminder interval for a timer still overdue after.
            current_keys.update(previous)
        if state_error is None:
            save_state(
                state_path,
                {"alerted": {k: v for k, v in alerted.items() if k in current_keys},
                 "updated_at": now},
            )

    if state_error is not None:
        facts = {**facts, "state_error": state_error}
        if verdict != "unknown":
            verdict, reason = "unknown", f"{state_error} (sweep result: {verdict.upper()}"\
                f"{': ' + reason if reason else ''})"
    _emit(verdict, reason, facts, args.json)
    if verdict == "unknown":
        return EXIT_UNKNOWN
    if verdict == "findings":
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
