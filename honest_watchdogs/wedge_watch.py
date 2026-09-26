"""Detect a scheduled launchd ONE-SHOT whose current run has outlived its own schedule.

macOS / launchd only (reads ``launchctl list``, ``ps`` and LaunchAgent plists). The
classification logic is pure and runs anywhere; the collection step takes an injectable command
runner so it can be tested without launchd.

Why this exists: launchd will not start a second instance of a job while one is running. So a
wedged scheduled job does not delay a cycle, it HALTS the schedule, silently and indefinitely.
``launchctl list`` keeps showing the job with ``LastExitStatus`` 0, which describes the last run
that finished, not the one that is stuck.

The distinction this turns on: a DAEMON is supposed to run for weeks, and a one-shot that has
been up for sixteen hours is broken. They are indistinguishable by uptime and trivially
distinguishable by their PLIST: a daemon carries ``KeepAlive`` and no schedule, a one-shot
carries a schedule. Classify by the declaration, never by the label or by how long it has run.
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from ._state import StateCorrupt, load_json_state, save_json_state
from .alerts import alert
from .exitcodes import EXIT_FINDINGS, EXIT_MISCONFIGURED, EXIT_OK, EXIT_UNKNOWN

LABEL_PREFIX_ENV = "WATCHDOG_LABEL_PREFIX"

# A one-shot should finish well inside its own period. This multiple is the slack before we
# call it wedged: generous, because a false page is how a watch gets muted.
WEDGE_MULTIPLE = 1.5
# Nothing scheduled should legitimately run for a day.
ABSOLUTE_CEILING_S = 24 * 3600

# A CADENCE CANNOT TELL YOU HOW LONG THE WORK TAKES. It says how OFTEN work starts. A daily job
# gets a cadence bound of 24h even when the job itself expects to finish in ten minutes, so a
# hang can halt its schedule for a day before this watch notices.
#
# So prefer a runtime the job DECLARES over one derived from its schedule. The convention is a
# line in the job's script such as ``# expect ~10 min``.
#
# DECLARED, never OBSERVED: a bound taken from how long the job has been running would let an
# already-wedged job enlarge its own bound and exonerate itself.
_DECLARED_RUNTIME_RE = re.compile(
    r"expect\s*~?\s*(\d+)\s*(sec|second|min|minute|hour|hr)", re.I
)
# Slack over a declared runtime. Tighter than WEDGE_MULTIPLE because a stated runtime is
# evidence about the work itself, not a proxy for it.
DECLARED_MULTIPLE = 2.0
# A declared runtime is a claim in a comment; never let it pull the bound below this floor.
MIN_DECLARED_BOUND_S = 300

# Re-nag rather than alert every tick: a pager that repeats every five minutes gets muted, and
# muting is how a long wedge stays invisible.
RENAG_S = 6 * 3600

#: Runs one command and returns ``(exit_code, stdout)``. A command that cannot be started or
#: times out must return a non-zero code, never a quiet empty success.
Runner = Callable[[Sequence[str]], tuple[int, str]]


@dataclass(frozen=True)
class Job:
    label: str
    pid: int
    elapsed_s: int
    plist: dict


@dataclass(frozen=True)
class Finding:
    label: str
    kind: str  # "wedged" | "unknown"
    detail: str


def period_seconds(plist: dict) -> int | None:
    """The job's own declared period, from its schedule. None if it has none.

    Derived from the DECLARED schedule, never from observed run times.
    """

    if "StartInterval" in plist:
        try:
            return max(1, int(plist["StartInterval"]))
        except (TypeError, ValueError):
            return None
    entries = plist.get("StartCalendarInterval")
    if entries is None:
        return None
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list) or not entries:
        return None
    minutes: list[int] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if "Day" in entry or "Weekday" in entry or "Month" in entry:
            return 24 * 3600  # sparser than daily; use the daily ceiling
        hour = entry.get("Hour")
        minute = int(entry.get("Minute") or 0)
        if hour is None:
            return 3600  # every hour at :MM
        minutes.append(int(hour) * 60 + minute)
    if not minutes:
        return None
    if len(minutes) == 1:
        return 24 * 3600
    minutes.sort()
    gaps = [b - a for a, b in zip(minutes, minutes[1:])]
    gaps.append(minutes[0] + 24 * 60 - minutes[-1])  # wrap midnight
    return max(60, min(gaps) * 60)


def declared_runtime_seconds(plist: dict) -> int | None:
    """Seconds the job's own script says it takes, or None.

    Reads the SCRIPT, not the interpreter: a first-match scan of ``ProgramArguments`` would pick
    ``/usr/bin/env`` or a virtualenv's ``python`` and find nothing.
    """

    argv = plist.get("ProgramArguments")
    if not isinstance(argv, list):
        return None
    for token in argv:
        if not isinstance(token, str) or not token.endswith((".py", ".sh", ".js", ".ts")):
            continue
        try:
            source = Path(token).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        match = _DECLARED_RUNTIME_RE.search(source)
        if not match:
            return None
        n = int(match.group(1))
        unit = match.group(2).lower()
        if unit.startswith(("hour", "hr")):
            return n * 3600
        if unit.startswith("sec"):
            return n
        return n * 60
    return None


def classify(job: Job) -> Finding | None:
    """A finding, or None when the job is fine. Never a silent pass on an unknown."""

    plist = job.plist
    if not plist:
        return Finding(job.label, "unknown", "plist unreadable; cannot classify. UNKNOWN, not clean.")

    has_keepalive = "KeepAlive" in plist
    period = period_seconds(plist)

    if period is None:
        if has_keepalive:
            return None  # a daemon: long uptime is correct
        return Finding(
            job.label, "unknown",
            "no schedule and no KeepAlive, yet a process is alive. Cannot derive an expected "
            "runtime, so this is UNKNOWN rather than healthy.",
        )

    if has_keepalive:
        # A schedule AND KeepAlive: launchd may relaunch it at any time, so its runtime cannot
        # be bounded from the schedule. Say so rather than guess.
        return Finding(
            job.label, "unknown",
            "carries BOTH a schedule and KeepAlive, so its runtime cannot be bounded from the "
            "schedule alone. UNKNOWN.",
        )

    declared = declared_runtime_seconds(plist)
    if declared is not None:
        bound = max(MIN_DECLARED_BOUND_S, min(int(declared * DECLARED_MULTIPLE), ABSOLUTE_CEILING_S))
        basis = f"its own DECLARED runtime {declared}s x{DECLARED_MULTIPLE}"
    else:
        bound = min(int(period * WEDGE_MULTIPLE), ABSOLUTE_CEILING_S)
        basis = (
            f"FALLBACK: period {period}s x{WEDGE_MULTIPLE} -- the job declares no runtime, and a "
            f"cadence cannot tell you how long the work takes, so this bound is weak"
        )
    if job.elapsed_s > bound:
        return Finding(
            job.label, "wedged",
            f"one-shot alive {job.elapsed_s}s, which is past {bound}s ({basis}). launchd will "
            f"not start another instance while this runs, so the schedule is HALTED, not delayed.",
        )
    return None


def parse_etime(text: str) -> int | None:
    """Parse ``ps -o etime=``: ``[[DD-]HH:]MM:SS``."""

    text = text.strip()
    if not text:
        return None
    days = 0
    if "-" in text:
        d, _, text = text.partition("-")
        try:
            days = int(d)
        except ValueError:
            return None
    try:
        nums = [int(p) for p in text.split(":")]
    except ValueError:
        return None
    while len(nums) < 3:
        nums.insert(0, 0)
    h, m, s = nums[-3], nums[-2], nums[-1]
    return days * 86400 + h * 3600 + m * 60 + s


def run_command(argv: Sequence[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(list(argv), capture_output=True, text=True, check=False, timeout=30)
    except subprocess.TimeoutExpired:
        return -1, ""
    except OSError:
        return 127, ""
    return proc.returncode, proc.stdout


def collect(
    agents_dir: Path,
    label_prefix: str,
    *,
    runner: Runner = run_command,
) -> tuple[list[Job], list[Finding]]:
    """Survey running jobs whose label starts with ``label_prefix``."""

    jobs: list[Job] = []
    problems: list[Finding] = []
    rc, out = runner(["launchctl", "list"])
    if rc != 0 or not out.strip():
        problems.append(Finding(
            "(all)", "unknown", f"launchctl list failed or returned nothing (rc={rc}); cannot survey."
        ))
        return jobs, problems
    loaded = 0
    for line in out.splitlines()[1:]:
        cols = line.split("\t")
        if len(cols) < 3:
            continue
        pid_s, label = cols[0].strip(), cols[2].strip()
        if not label.startswith(label_prefix):
            continue
        loaded += 1
        if not pid_s.isdigit():
            continue  # loaded, not running: nothing to bound
        ps_rc, ps_out = runner(["ps", "-o", "etime=", "-p", pid_s])
        elapsed = parse_etime(ps_out) if ps_rc == 0 else None
        if elapsed is None:
            if ps_rc == 1 and not ps_out.strip():
                # ps -p exits 1 with no output when no such process exists: the job finished
                # between the listing and the probe. That is not a fault.
                continue
            # ps failed, timed out, is missing, or printed something unparseable. The job is
            # running and we could not measure how long: UNKNOWN, never dropped.
            problems.append(Finding(
                label, "unknown",
                f"could not measure the runtime of pid {pid_s}: ps exited {ps_rc} "
                f"with output {ps_out.strip()[:80]!r}. UNKNOWN, not clean.",
            ))
            continue
        try:
            plist = plistlib.loads((agents_dir / f"{label}.plist").read_bytes())
        except Exception:
            plist = {}
        jobs.append(Job(label, int(pid_s), elapsed, plist))
    if loaded == 0:
        # Zero RUNNING jobs is normal between runs. Zero LOADED jobs means the prefix matches
        # nothing, and a typo in it must not read as a clean survey.
        problems.append(Finding(
            "(all)", "unknown",
            f"no loaded launchd job matches {label_prefix!r}; coverage is unknown",
        ))
    return jobs, problems


def dedupe_key_for(kind: str, label: str) -> str:
    return f"launchd-wedge-watch/{kind}/{label}"


def deliver(findings: list[Finding], state_path: Path, *, now: float) -> int:
    """Alert for each finding, at most once per RENAG_S. Returns how many were delivered.

    The re-nag latch advances only on a successful delivery. A failed alert stays due on the
    next tick instead of consuming the six-hour window in silence. Raises
    :class:`StateCorrupt` (before sending anything) if the state file exists but is unusable.
    """

    state = load_json_state(state_path)
    sent = send_alerts(findings, state, now=now)
    save_json_state(state_path, state)
    return sent


def send_alerts(findings: list[Finding], state: dict, *, now: float) -> int:
    """Send due alerts and advance ``state`` latches in place for the delivered ones."""

    sent = 0
    for finding in findings:
        key = dedupe_key_for(finding.kind, finding.label)
        last = state.get(key)
        if isinstance(last, (int, float)) and now - last < RENAG_S:
            continue
        result = alert(
            "warn" if finding.kind == "unknown" else "critical",
            "launchd-wedge-watch",
            (
                f"launchd WEDGED: {finding.label} -- its schedule is HALTED, not delayed"
                if finding.kind == "wedged"
                else f"launchd wedge watch CANNOT MEASURE {finding.label}"
            ),
            details=finding.detail,
            dedupe_key=key,
            tags=("launchd", "wedge"),
        )
        if not result.success:
            continue
        state[key] = now
        sent += 1
    return sent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="launchd-wedge-watch",
        description=(__doc__ or "").split("\n\n")[0],
    )
    parser.add_argument(
        "--label-prefix",
        default=os.environ.get(LABEL_PREFIX_ENV),
        help=f"only survey jobs whose label starts with this (or set {LABEL_PREFIX_ENV}); "
        "required, because a default that matches nothing would read as clean",
    )
    parser.add_argument("--agents-dir", type=Path, default=Path("~/Library/LaunchAgents"))
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--state-file", type=Path,
        default=Path("~/.local/state/honest-watchdogs/launchd-wedge-watch.json"),
    )
    parser.add_argument("--no-alert", action="store_true", help="classify only; do not alert")
    args = parser.parse_args(argv)
    if not args.label_prefix:
        parser.print_usage(sys.stderr)
        print(f"launchd-wedge-watch: --label-prefix (or {LABEL_PREFIX_ENV}) is required",
              file=sys.stderr)
        return EXIT_MISCONFIGURED

    jobs, findings = collect(args.agents_dir.expanduser(), args.label_prefix)
    for job in jobs:
        finding = classify(job)
        if finding is not None:
            findings.append(finding)

    wedged = [f for f in findings if f.kind == "wedged"]
    unknown = [f for f in findings if f.kind == "unknown"]

    # The state file is read on every alerting run, not only when there is something to send:
    # a corrupt latch record must surface as UNKNOWN on a quiet day too.
    state_error: str | None = None
    delivered = 0
    if not args.no_alert:
        now = time.time()
        try:
            delivered = deliver(findings, args.state_file.expanduser(), now=now)
        except StateCorrupt as exc:
            # Alert anyway, unlatched (nothing is saved): repeated alerts are better than
            # silence, and the file is left untouched for inspection.
            state_error = str(exc)
            delivered = send_alerts(findings, {}, now=now)

    if args.json:
        print(json.dumps({
            "surveyed": len(jobs),
            "wedged": [f.__dict__ for f in wedged],
            "unknown": [f.__dict__ for f in unknown],
            "state_error": state_error,
        }, indent=2))
    else:
        for f in wedged:
            print(f"WEDGED: {f.label}: {f.detail}")
        for f in unknown:
            print(f"UNKNOWN: {f.label}: {f.detail}")
        if state_error:
            print(f"UNKNOWN: {state_error}; alerts were sent without re-alert latches")
        print(f"surveyed {len(jobs)} running {args.label_prefix}* jobs: "
              f"{len(wedged)} wedged, {len(unknown)} unknown")
    if findings and not args.no_alert:
        print(f"alerts delivered: {delivered} (others inside the {RENAG_S}s re-nag window "
              "or failed)", file=sys.stderr)

    # UNKNOWN outranks WEDGED: "I could not look" must not be reported as "I looked".
    if unknown or state_error:
        return EXIT_UNKNOWN
    return EXIT_FINDINGS if wedged else EXIT_OK

if __name__ == "__main__":
    raise SystemExit(main())
