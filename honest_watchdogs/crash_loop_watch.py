"""Detect launchd jobs that are crash-looping, without treating normal restarts as failures.

macOS / launchd only for collection (``launchctl list`` and ``launchctl print``); evaluation is
pure and runs anywhere. By default it watches the machine it runs on. ``--host`` adds machines
whose launchd inventory is read over ``ssh -o BatchMode=yes`` FROM this one, so alert
credentials never have to be copied to them. A host that cannot be measured is UNKNOWN and
exits 3: an unreachable host reporting calm is the failure this watch exists to surface.

How a crash loop is recognised: launchd's per-job ``runs`` counter must ADVANCE between
observations, with a positive ``last exit code``, at least ``--threshold`` times inside a
bounded ``--window-seconds``. One observation per distinct run-counter advance, so a single
long sample cannot be counted twice. Exit 0, signal-based restarts (including a deliberate
``kickstart -k``), and a run-counter reset (reboot, reload) all end the pattern.

Two further rules:

* **An incident that never ends must not go quiet.** A crash loop is paged once, then re-paged
  every ``--reminder-seconds`` while it continues. Alert-once is correct for a condition that
  ends; for one that does not, the first page is also the last.
* **Failed delivery stays retryable.** The incident latch advances only when the page was
  delivered, and the error record names each sink's failure reason.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

from .alerts import AlertConfigError, AlertResult, alert, failure_detail
from .exitcodes import EXIT_FINDINGS, EXIT_MISCONFIGURED, EXIT_OK, EXIT_UNKNOWN

SCHEMA_VERSION = 1
DEFAULT_LABEL_PREFIX = "com.example."
LABEL_PREFIX_ENV = "WATCHDOG_LABEL_PREFIX"
DEFAULT_WINDOW_SECONDS = 600
DEFAULT_THRESHOLD = 3
DEFAULT_LAUNCHCTL_TIMEOUT_SECONDS = 10.0
#: How long a crash-loop incident may stay quiet after its last delivered page.
DEFAULT_REMINDER_SECONDS = 21600
DEFAULT_STATE_PATH = Path("~/.local/state/honest-watchdogs/launchd-crash-loop-watch.json")
NONZERO_FINDINGS_ENV = "WATCHDOG_NONZERO_FINDINGS_LABELS"

Verdict = Literal["healthy", "observing", "crash_looping", "expected_nonzero", "never_run", "unknown"]

_HEADER_RE = re.compile(r"^gui/(?P<uid>\d+)/(?P<label>[^\s=]+) = \{$")
_TOP_LEVEL_FIELD_RE = re.compile(r"^\t(?P<key>[^=]+?) = (?P<value>.*)$")
_INTEGER_RE = re.compile(r"^-?[0-9]+$")


class LaunchdHealthError(RuntimeError):
    """Base error for an observation whose coverage cannot be trusted."""


class LaunchdDiscoveryError(LaunchdHealthError):
    """The scoped launchd inventory is unavailable."""


class LaunchdParseError(LaunchdHealthError):
    """A per-job launchctl artifact lacks required fields."""


class HealthStateError(LaunchdHealthError):
    """Bounded-window evidence cannot be loaded or saved safely."""


@dataclass(frozen=True, kw_only=True)
class WatchConfig:
    """Runtime policy for one watcher invocation."""

    label_prefix: str = DEFAULT_LABEL_PREFIX
    state_path: Path = DEFAULT_STATE_PATH
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    threshold: int = DEFAULT_THRESHOLD
    launchctl_timeout_seconds: float = DEFAULT_LAUNCHCTL_TIMEOUT_SECONDS
    nonzero_findings_labels: frozenset[str] = frozenset()
    reminder_seconds: int = DEFAULT_REMINDER_SECONDS
    no_alert: bool = False
    show_all: bool = False
    #: Print the JSON report on every run (healthy included) and no human table.
    json_output: bool = False
    fail_on_crash_loop: bool = False
    hosts: tuple[str, ...] = ()
    #: Skip the local pass and check only the ``--host`` machines. For a dedicated per-host job
    #: that must not re-classify the watching machine's jobs without its exemptions.
    remote_only: bool = False

    def __post_init__(self) -> None:
        if not self.label_prefix or any(c.isspace() for c in self.label_prefix):
            raise ValueError("label_prefix must be non-empty and contain no whitespace")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.threshold < 2:
            raise ValueError("threshold must be at least 2")
        if self.launchctl_timeout_seconds <= 0:
            raise ValueError("launchctl_timeout_seconds must be positive")
        if self.reminder_seconds < 0:
            raise ValueError("reminder_seconds must not be negative")
        invalid_hosts = sorted(
            h for h in self.hosts if not h or any(c.isspace() for c in h) or "/" in h
        )
        if invalid_hosts:
            raise ValueError(
                "remote hosts must be non-empty names without whitespace or '/': "
                + ", ".join(repr(h) for h in invalid_hosts)
            )
        if len(set(self.hosts)) != len(self.hosts):
            raise ValueError("duplicate --host entries are not allowed")
        if self.remote_only and not self.hosts:
            raise ValueError("--remote-only requires at least one --host")
        invalid = sorted(
            label for label in self.nonzero_findings_labels
            if not label.startswith(self.label_prefix) or any(c.isspace() for c in label)
        )
        if invalid:
            raise ValueError(
                f"nonzero-on-findings labels must be exact {self.label_prefix}* labels: "
                + ", ".join(invalid)
            )


@dataclass(frozen=True, kw_only=True)
class CommandArtifact:
    """Captured output of one command."""

    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    error: str = ""


@dataclass(frozen=True, kw_only=True)
class LaunchdJobSnapshot:
    """Fields read from one ``launchctl print gui/$uid/$label`` artifact."""

    label: str
    state: str
    runs: int
    last_exit_code: int | None
    last_exit_raw: str
    pid: int | None
    last_terminating_signal: str | None
    run_interval_seconds: int | None
    has_event_triggers: bool

    @property
    def periodic(self) -> bool:
        return self.run_interval_seconds is not None or self.has_event_triggers


@dataclass(frozen=True, kw_only=True)
class UnknownObservation:
    """A discovered label whose per-job artifact was unreadable."""

    label: str
    reason: str


Observation = LaunchdJobSnapshot | UnknownObservation


@dataclass(frozen=True, kw_only=True)
class _HostRun:
    display: str
    report: dict[str, object]
    exit_code: int
    next_state: Mapping[str, object]
    #: The inventory could not be read at all. The host is UNKNOWN and its prior evidence must
    #: be preserved rather than wiped by the next save.
    discovery_failed: bool = False
    #: Set only for a REMOTE host that could not be measured; drives the unreachable page.
    unreachable_reason: str | None = None


@dataclass(frozen=True, kw_only=True)
class EvaluatedJob:
    label: str
    state: str
    last_exit_code: int | None
    last_exit_raw: str
    runs: int | None
    pid: int | None
    periodic: bool | None
    contract: str
    verdict: Verdict
    reason: str
    respawn_restart_evidence: Mapping[str, object]

    def as_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "state": self.state,
            "last_exit_code": self.last_exit_code,
            "last_exit_raw": self.last_exit_raw,
            "runs": self.runs,
            "pid": self.pid,
            "periodic": self.periodic,
            "contract": self.contract,
            "verdict": self.verdict,
            "reason": self.reason,
            "respawn_restart_evidence": dict(self.respawn_restart_evidence),
        }


@dataclass(frozen=True, kw_only=True)
class PendingCrashLoopAlert:
    label: str
    exit_code: int
    count: int
    window_seconds: int
    runs_advanced: int


@dataclass(frozen=True, kw_only=True)
class Evaluation:
    generated_at: float
    uid: int
    jobs: tuple[EvaluatedJob, ...]
    next_state: dict[str, object]
    pending_alerts: tuple[PendingCrashLoopAlert, ...]

    @property
    def crash_looping(self) -> tuple[str, ...]:
        return tuple(job.label for job in self.jobs if job.verdict == "crash_looping")

    @property
    def unknown(self) -> tuple[str, ...]:
        return tuple(job.label for job in self.jobs if job.verdict == "unknown")


class CrashLoopAlertSender(Protocol):
    def __call__(
        self,
        *,
        label: str,
        exit_code: int,
        observed_nonzero_exit_count: int,
        window_seconds: int,
        runs_advanced: int,
        now: datetime,
        host: str | None = None,
    ) -> AlertResult: ...


def alert_crash_loop(
    *,
    label: str,
    exit_code: int,
    observed_nonzero_exit_count: int,
    window_seconds: int,
    runs_advanced: int,
    host: str | None = None,
    now: datetime | None = None,
) -> AlertResult:
    """Page for a crash loop with the evidence in the page itself.

    A dedicated path, so a caller cannot omit the label, exit code, count or window.
    """

    label = " ".join(label.split())
    host = " ".join((host or "").split())
    if not label:
        raise AlertConfigError("label must not be empty")
    if exit_code <= 0:
        raise AlertConfigError("crash-loop exit_code must be positive")
    if observed_nonzero_exit_count < 2:
        raise AlertConfigError("observed_nonzero_exit_count must be at least 2")
    if window_seconds <= 0:
        raise AlertConfigError("window_seconds must be positive")
    if runs_advanced < observed_nonzero_exit_count:
        raise AlertConfigError("runs_advanced must cover every observed non-zero exit")
    # The dedupe key names the host when one is known: two machines can run the same label, and
    # a label-only key would let the first host's page swallow the second host's.
    dedupe_key = (
        f"launchd-crash-loop-watch/crash-loop/{host}/{label}"
        if host
        else f"launchd-crash-loop-watch/crash-loop/{label}"
    )
    prefix = f"[{host}] " if host else ""
    return alert(
        "page",
        "launchd-crash-loop-watch",
        f"{prefix}{label} crash-looping: exit code {exit_code}; "
        f"{observed_nonzero_exit_count} non-zero exits observed in {window_seconds}s",
        details={
            "job_label": label,
            "exit_code": exit_code,
            "observed_nonzero_exit_count": observed_nonzero_exit_count,
            "window_seconds": window_seconds,
            "runs_advanced": runs_advanced,
            "evidence_basis": "distinct launchd run-counter advances whose latest exit code was non-zero",
        },
        dedupe_key=dedupe_key,
        tags=("launchd", "crash-loop"),
        now=now,
    )


# --------------------------------------------------------------------------- parsing


def parse_launchctl_list(stdout: str, label_prefix: str) -> tuple[str, ...]:
    """Return the labels that start with ``label_prefix``.

    An empty scoped inventory is a coverage failure, not an all-clear. Listing is discovery
    only; every label is inspected with ``launchctl print`` before it receives a verdict.
    """

    labels: set[str] = set()
    for raw_line in stdout.splitlines():
        parts = raw_line.split(maxsplit=2)
        if len(parts) != 3:
            continue
        label = parts[2].strip()
        if label.startswith(label_prefix):
            labels.add(label)
    if not labels:
        raise LaunchdDiscoveryError(
            f"launchctl discovery returned no {label_prefix}* jobs; coverage is unknown"
        )
    return tuple(sorted(labels))


def parse_launchctl_print(stdout: str, *, expected_label: str | None = None) -> LaunchdJobSnapshot:
    """Parse direct fields from ``launchctl print`` output.

    Direct fields have exactly one leading tab. That avoids confusing nested coalition ``state``
    or ``active count`` fields with the job-level fields of the same name.
    """

    lines = stdout.splitlines()
    if not lines:
        raise LaunchdParseError("launchctl print returned empty stdout")
    header = _HEADER_RE.fullmatch(lines[0])
    if header is None:
        raise LaunchdParseError("launchctl print output has no gui/$uid/$label header")
    label = header.group("label")
    if expected_label is not None and label != expected_label:
        raise LaunchdParseError(f"launchctl print returned label {label!r}, expected {expected_label!r}")

    fields: dict[str, str] = {}
    for line in lines[1:]:
        match = _TOP_LEVEL_FIELD_RE.fullmatch(line)
        if match is not None:
            fields.setdefault(match.group("key"), match.group("value"))

    state = fields.get("state", "").strip()
    if not state:
        raise LaunchdParseError(f"{label}: launchctl print omitted job-level state")
    runs = _required_nonnegative_int(fields.get("runs"), field="runs", label=label)
    last_exit_raw = fields.get("last exit code", "").strip()
    return LaunchdJobSnapshot(
        label=label,
        state=state,
        runs=runs,
        last_exit_code=_optional_int(last_exit_raw),
        last_exit_raw=last_exit_raw,
        pid=_optional_int(fields.get("pid", "")),
        last_terminating_signal=fields.get("last terminating signal"),
        run_interval_seconds=_run_interval(fields.get("run interval", ""), label=label),
        has_event_triggers="\n\tevent triggers = {" in f"\n{stdout}",
    )


def observations_from_artifacts(
    labels: Sequence[str],
    artifacts: Mapping[str, CommandArtifact],
) -> tuple[Observation, ...]:
    observations: list[Observation] = []
    for label in labels:
        artifact = artifacts.get(label)
        if artifact is None:
            observations.append(UnknownObservation(
                label=label, reason="launchctl print artifact missing after discovery"))
            continue
        if artifact.error:
            observations.append(UnknownObservation(label=label, reason=artifact.error))
            continue
        if artifact.returncode != 0:
            detail = _safe_detail(artifact.stderr) or "no stderr"
            observations.append(UnknownObservation(
                label=label, reason=f"launchctl print exited {artifact.returncode}: {detail}"))
            continue
        try:
            observations.append(parse_launchctl_print(artifact.stdout, expected_label=label))
        except LaunchdParseError as exc:
            observations.append(UnknownObservation(label=label, reason=str(exc)))
    return tuple(observations)


# --------------------------------------------------------------------------- collection


def capture_launchctl_artifacts(
    *,
    uid: int,
    timeout_seconds: float,
    label_prefix: str,
    host: str | None = None,
) -> tuple[tuple[str, ...], dict[str, CommandArtifact]]:
    """Discover and print current-user launchd jobs, locally or over ssh. No root required."""

    if host is None:
        list_artifact = _run_launchctl(("list",), timeout_seconds=timeout_seconds)

        def printer(arguments: Sequence[str]) -> CommandArtifact:
            return _run_launchctl(arguments, timeout_seconds=timeout_seconds)

        scope = ""
    else:
        list_artifact = _run_ssh(host, ("launchctl", "list"), timeout_seconds=timeout_seconds)

        def printer(arguments: Sequence[str]) -> CommandArtifact:
            return _run_ssh(host, ("launchctl", *arguments), timeout_seconds=timeout_seconds)

        scope = f"{host}: "
    if list_artifact.error:
        raise LaunchdDiscoveryError(list_artifact.error)
    if list_artifact.returncode != 0:
        detail = _safe_detail(list_artifact.stderr) or "no stderr"
        raise LaunchdDiscoveryError(f"{scope}launchctl list exited {list_artifact.returncode}: {detail}")
    labels = parse_launchctl_list(list_artifact.stdout, label_prefix)
    artifacts = {label: printer(("print", f"gui/{uid}/{label}")) for label in labels}
    return labels, artifacts


def _remote_uid(host: str, *, timeout_seconds: float) -> int:
    artifact = _run_ssh(host, ("id", "-u"), timeout_seconds=timeout_seconds)
    if artifact.error:
        raise LaunchdDiscoveryError(artifact.error)
    if artifact.returncode != 0:
        detail = _safe_detail(artifact.stderr) or "no stderr"
        raise LaunchdDiscoveryError(f"{host}: id -u exited {artifact.returncode}: {detail}")
    raw = artifact.stdout.strip()
    try:
        return int(raw)
    except ValueError:
        raise LaunchdDiscoveryError(f"{host}: id -u returned {raw!r}") from None


def _run_ssh(host: str, remote_argv: Sequence[str], *, timeout_seconds: float) -> CommandArtifact:
    """Run one remote command; every failure mode stays explicit.

    ``BatchMode=yes`` makes a missing key fail instead of hanging on a password prompt, and
    ``ConnectTimeout`` bounds the TCP phase.
    """

    connect_timeout = max(1, math.ceil(timeout_seconds))
    command = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={connect_timeout}",
               host, *remote_argv]
    subprocess_timeout = timeout_seconds + 10
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False,
                                   timeout=subprocess_timeout)
    except subprocess.TimeoutExpired:
        return CommandArtifact(
            returncode=None,
            error=f"ssh {host} {' '.join(remote_argv)} timed out after {subprocess_timeout:g}s",
        )
    except OSError as exc:
        return CommandArtifact(returncode=None, error=f"cannot run ssh to {host}: {exc}")
    return CommandArtifact(returncode=completed.returncode, stdout=completed.stdout,
                           stderr=completed.stderr)


def _run_launchctl(arguments: Sequence[str], *, timeout_seconds: float) -> CommandArtifact:
    try:
        completed = subprocess.run(("launchctl", *arguments), capture_output=True, text=True,
                                   check=False, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return CommandArtifact(
            returncode=None,
            error=f"launchctl {' '.join(arguments)} timed out after {timeout_seconds:g}s",
        )
    except OSError as exc:
        return CommandArtifact(returncode=None,
                               error=f"cannot run launchctl {' '.join(arguments)}: {exc}")
    return CommandArtifact(returncode=completed.returncode, stdout=completed.stdout,
                           stderr=completed.stderr)


# --------------------------------------------------------------------------- state


def empty_state() -> dict[str, object]:
    return {"schema_version": SCHEMA_VERSION, "jobs": {}}


def load_state(path: Path) -> dict[str, object]:
    """Load bounded-window evidence, failing loudly on unreadable or corrupt state.

    A corrupt state file is never silently replaced: an empty baseline would quietly restart
    every job's evidence window.
    """

    expanded = path.expanduser()
    try:
        raw = expanded.read_text(encoding="utf-8")
    except FileNotFoundError:
        return empty_state()
    except OSError as exc:
        raise HealthStateError(f"cannot read state file {expanded}: {exc}") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HealthStateError(f"state file {expanded} is invalid JSON: {exc}") from exc
    return _validated_state(value, path=expanded)


def save_state(path: Path, state: Mapping[str, object]) -> None:
    """Atomically replace the evidence state, owner-only permissions."""

    expanded = path.expanduser()
    try:
        expanded.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(dir=expanded.parent, prefix=f".{expanded.name}.",
                                              suffix=".tmp")
    except OSError as exc:
        raise HealthStateError(f"cannot prepare state file {expanded}: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(state, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, expanded)
    except OSError as exc:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise HealthStateError(f"cannot save state file {expanded}: {exc}") from exc


# --------------------------------------------------------------------------- evaluation


def evaluate_observations(
    observations: Sequence[Observation],
    previous_state: Mapping[str, object],
    *,
    config: WatchConfig,
    now: float,
    uid: int,
) -> Evaluation:
    """Classify one sample against prior bounded-window evidence."""

    prior_jobs = _validated_state(previous_state, path=None)["jobs"]
    assert isinstance(prior_jobs, dict)
    next_jobs: dict[str, object] = {}
    jobs: list[EvaluatedJob] = []
    pending_alerts: list[PendingCrashLoopAlert] = []

    for observation in sorted(observations, key=lambda item: item.label):
        prior = prior_jobs.get(observation.label)
        prior_entry = prior if isinstance(prior, dict) else None
        if isinstance(observation, UnknownObservation):
            if prior_entry is not None:
                next_jobs[observation.label] = prior_entry
            jobs.append(_unknown_job(observation, window_seconds=config.window_seconds))
            continue
        evaluated, next_entry, pending = _evaluate_snapshot(
            observation, prior_entry=prior_entry, config=config, now=now
        )
        next_jobs[observation.label] = next_entry
        jobs.append(evaluated)
        if pending is not None:
            pending_alerts.append(pending)

    return Evaluation(
        generated_at=now,
        uid=uid,
        jobs=tuple(jobs),
        next_state={"schema_version": SCHEMA_VERSION, "updated_at": _iso_timestamp(now),
                    "jobs": next_jobs},
        pending_alerts=tuple(pending_alerts),
    )


def state_failure_evaluation(
    observations: Sequence[Observation],
    *,
    config: WatchConfig,
    now: float,
    uid: int,
    reason: str,
) -> Evaluation:
    """Every discovered job is UNKNOWN when history state is unavailable."""

    jobs = tuple(
        _unknown_job(
            UnknownObservation(label=o.label, reason=f"bounded-window state unavailable: {reason}"),
            window_seconds=config.window_seconds,
        )
        for o in sorted(observations, key=lambda item: item.label)
    )
    return Evaluation(generated_at=now, uid=uid, jobs=jobs, next_state=empty_state(),
                      pending_alerts=())


def deliver_pending_alerts(
    evaluation: Evaluation,
    *,
    config: WatchConfig,
    alert_sender: CrashLoopAlertSender | None = None,
    origin_host: str | None = None,
) -> tuple[dict[str, object], ...]:
    """Deliver each due crash-loop page; failed deliveries remain retryable.

    ``origin_host`` names the host the loop was observed on; it defaults to this machine.
    """

    if config.no_alert:
        return ()
    errors: list[dict[str, object]] = []
    for pending in evaluation.pending_alerts:
        try:
            arguments = {
                "label": pending.label,
                "exit_code": pending.exit_code,
                "observed_nonzero_exit_count": pending.count,
                "window_seconds": pending.window_seconds,
                "runs_advanced": pending.runs_advanced,
                "now": datetime.fromtimestamp(evaluation.generated_at, tz=UTC),
                "host": origin_host if origin_host is not None else _short_hostname(),
            }
            sender = alert_sender if alert_sender is not None else alert_crash_loop
            result = sender(**arguments)
        except Exception as exc:
            errors.append({"scope": "alert", "label": pending.label,
                           "error": f"{type(exc).__name__}: {_safe_detail(str(exc))}"})
            continue
        if not result.success:
            # Carry each sink's failure reason. This record is the ONLY artifact a failed
            # delivery produces; one that says only "unsuccessful" makes the cause invisible in
            # exactly the log written to diagnose it.
            errors.append({"scope": "alert", "label": pending.label,
                           "error": f"alert delivery returned unsuccessful: {failure_detail(result)}"})
            continue
        _mark_incident_alerted(evaluation.next_state, pending.label, evaluation.generated_at)
    return tuple(errors)


def _policy_dict(config: WatchConfig) -> dict[str, object]:
    return {
        "label_prefix": config.label_prefix,
        "threshold": config.threshold,
        "window_seconds": config.window_seconds,
        "nonzero_findings_labels": sorted(config.nonzero_findings_labels),
        "reminder_seconds": config.reminder_seconds,
        "evidence_basis": "one lower-bound non-zero exit observation per distinct launchd "
        "run-counter advance",
    }


def report_dict(
    evaluation: Evaluation,
    *,
    config: WatchConfig,
    errors: Sequence[Mapping[str, object]] = (),
) -> dict[str, object]:
    counts = Counter(job.verdict for job in evaluation.jobs)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _iso_timestamp(evaluation.generated_at),
        "uid": evaluation.uid,
        "policy": _policy_dict(config),
        "summary": {
            "total": len(evaluation.jobs),
            "by_verdict": dict(sorted(counts.items())),
            "crash_looping": list(evaluation.crash_looping),
            "unknown": list(evaluation.unknown),
            "coverage_complete": not evaluation.unknown and not errors,
            "error_count": len(errors),
        },
        "jobs": [job.as_dict() for job in evaluation.jobs],
        "errors": [dict(error) for error in errors],
    }


def format_human_table(report: Mapping[str, object]) -> str:
    raw_jobs = report.get("jobs")
    jobs = raw_jobs if isinstance(raw_jobs, list) else []
    headers = ("LABEL", "STATE", "EXIT", "RUNS", "dRUNS", "NZ/WINDOW", "VERDICT")
    rows: list[tuple[str, ...]] = []
    for raw_job in jobs:
        if not isinstance(raw_job, dict):
            continue
        evidence = raw_job.get("respawn_restart_evidence")
        ev = evidence if isinstance(evidence, dict) else {}
        label = str(raw_job.get("label", "?"))
        if raw_job.get("host"):
            label = f"{raw_job['host']}/{label}"
        rows.append((
            label,
            str(raw_job.get("state", "?")),
            _display_value(raw_job.get("last_exit_code")),
            _display_value(raw_job.get("runs")),
            _display_value(ev.get("runs_delta")),
            f"{ev.get('observed_nonzero_exit_count', 0)}/{ev.get('window_seconds', '?')}s",
            str(raw_job.get("verdict", "unknown")),
        ))
    widths = [len(h) for h in headers]
    for row in rows:
        for i, value in enumerate(row):
            widths[i] = max(widths[i], len(value))
    rendered = ["  ".join(v.ljust(widths[i]) for i, v in enumerate(headers))]
    rendered.append("  ".join("-" * w for w in widths))
    rendered.extend("  ".join(v.ljust(widths[i]) for i, v in enumerate(row)) for row in rows)
    summary = report.get("summary")
    sm = summary if isinstance(summary, dict) else {}
    rendered.append(
        "crash_looping=" + json.dumps(sm.get("crash_looping", []), separators=(",", ":"))
        + " unknown=" + json.dumps(sm.get("unknown", []), separators=(",", ":"))
    )
    return "\n".join(rendered)


def should_emit_report(report: Mapping[str, object], *, show_all: bool) -> bool:
    """Healthy, complete coverage is silent unless ``--show-all``; anything else speaks."""

    summary = report.get("summary")
    sm = summary if isinstance(summary, dict) else {}
    return bool(show_all or sm.get("crash_looping") or sm.get("unknown") or report.get("errors"))


# --------------------------------------------------------------------------- run


def run_once(
    config: WatchConfig,
    *,
    uid: int | None = None,
    now: float | None = None,
) -> tuple[dict[str, object], int]:
    """One observation pass: returns the report and the exit code.

    Without ``hosts``: this machine only. With ``hosts``: this machine plus every remote
    (or only the remotes with ``remote_only``), merged into one report where every finding is
    host-qualified and a host that cannot be measured exits 3 however clean the rest looks.
    """

    observed_at = time.time() if now is None else now
    current_uid = os.getuid() if uid is None else uid
    if config.hosts:
        return _run_multi_host(config, local_uid=current_uid, now=observed_at)
    try:
        labels, artifacts = capture_launchctl_artifacts(
            uid=current_uid, timeout_seconds=config.launchctl_timeout_seconds,
            label_prefix=config.label_prefix,
        )
    except LaunchdDiscoveryError as exc:
        return _discovery_failure_report(config=config, uid=current_uid, now=observed_at,
                                         reason=str(exc)), EXIT_UNKNOWN
    observations = observations_from_artifacts(labels, artifacts)
    try:
        previous_state = load_state(config.state_path)
    except HealthStateError as exc:
        evaluation = state_failure_evaluation(observations, config=config, now=observed_at,
                                              uid=current_uid, reason=str(exc))
        return report_dict(evaluation, config=config,
                           errors=({"scope": "state", "error": str(exc)},)), EXIT_UNKNOWN

    evaluation = evaluate_observations(observations, previous_state, config=config,
                                       now=observed_at, uid=current_uid)
    errors = list(deliver_pending_alerts(evaluation, config=config))
    try:
        save_state(config.state_path, evaluation.next_state)
    except HealthStateError as exc:
        errors.append({"scope": "state", "error": str(exc)})

    report = report_dict(evaluation, config=config, errors=errors)
    if evaluation.unknown or errors:
        return report, EXIT_UNKNOWN
    if evaluation.crash_looping and config.fail_on_crash_loop:
        return report, EXIT_FINDINGS
    return report, EXIT_OK


def _short_hostname() -> str:
    return socket.gethostname().split(".", maxsplit=1)[0]


def _host_state_slice(state: Mapping[str, object], *, prefix: str) -> dict[str, object]:
    """One host's evidence from the shared state file.

    Remote entries are keyed ``<host>/<label>`` so two machines running the same label keep
    independent baselines instead of corrupting each other's run counters. Local keys stay
    unprefixed.
    """

    jobs = _validated_state(state, path=None)["jobs"]
    assert isinstance(jobs, dict)
    if not prefix:
        return {"schema_version": SCHEMA_VERSION, "jobs": dict(jobs)}
    return {
        "schema_version": SCHEMA_VERSION,
        "jobs": {label[len(prefix):]: entry for label, entry in jobs.items()
                 if isinstance(label, str) and label.startswith(prefix)},
    }


def _run_single_host(
    config: WatchConfig,
    *,
    host: str | None,
    local_uid: int,
    now: float,
    state: Mapping[str, object] | None,
    state_error: str | None,
) -> _HostRun:
    display = host if host is not None else _short_hostname()
    try:
        if host is None:
            observed_uid = local_uid
            labels, artifacts = capture_launchctl_artifacts(
                uid=local_uid, timeout_seconds=config.launchctl_timeout_seconds,
                label_prefix=config.label_prefix,
            )
        else:
            observed_uid = _remote_uid(host, timeout_seconds=config.launchctl_timeout_seconds)
            labels, artifacts = capture_launchctl_artifacts(
                uid=observed_uid, timeout_seconds=config.launchctl_timeout_seconds,
                label_prefix=config.label_prefix, host=host,
            )
    except LaunchdDiscoveryError as exc:
        reason = f"{display}: {exc}" if host is not None else str(exc)
        return _HostRun(
            display=display,
            report=_discovery_failure_report(config=config, uid=local_uid, now=now, reason=reason),
            exit_code=EXIT_UNKNOWN,
            next_state={},
            discovery_failed=True,
            unreachable_reason=reason if host is not None else None,
        )

    observations = observations_from_artifacts(labels, artifacts)

    if host is not None and observations and all(
        isinstance(item, UnknownObservation) for item in observations
    ):
        # Transport failure AFTER discovery: listing succeeded but every per-job print failed
        # (connection reset mid-loop). The host gave no measurable inventory, so per-job
        # unknowns would page nothing and leave only a log line. Treat it exactly like a
        # discovery failure: UNKNOWN, exit 3, page, preserve evidence.
        detail = "; ".join(f"{i.label}: {_safe_detail(i.reason)}" for i in observations[:3])
        reason = f"{display}: launchctl print failed for every discovered job ({detail})"
        return _HostRun(
            display=display,
            report=_discovery_failure_report(config=config, uid=local_uid, now=now, reason=reason),
            exit_code=EXIT_UNKNOWN,
            next_state={},
            discovery_failed=True,
            unreachable_reason=reason,
        )

    if state is None:
        reason = state_error or "bounded-window state unavailable"
        evaluation = state_failure_evaluation(observations, config=config, now=now,
                                              uid=observed_uid, reason=reason)
        return _HostRun(
            display=display,
            report=report_dict(evaluation, config=config, errors=({"scope": "state", "error": reason},)),
            exit_code=EXIT_UNKNOWN,
            next_state=evaluation.next_state,
        )

    evaluation = evaluate_observations(observations, state, config=config, now=now, uid=observed_uid)
    errors = list(deliver_pending_alerts(evaluation, config=config, origin_host=host))
    if evaluation.unknown or errors:
        exit_code = EXIT_UNKNOWN
    elif evaluation.crash_looping and config.fail_on_crash_loop:
        exit_code = EXIT_FINDINGS
    else:
        exit_code = EXIT_OK
    return _HostRun(
        display=display,
        report=report_dict(evaluation, config=config, errors=errors),
        exit_code=exit_code,
        next_state=evaluation.next_state,
    )


def _alert_unreachable_host(*, display: str, reason: str, config: WatchConfig) -> dict[str, object] | None:
    """Page for a remote host whose inventory cannot be read at all.

    A host nobody can see reports nothing, and nothing reads as calm. A log line alone repeats
    that failure, so an unmeasurable host alerts (bounded by the alert library's dedupe window).
    Severity is ``critical`` rather than ``page``: during a sustained outage there is often
    nothing to do until the host is restored.
    """

    if config.no_alert:
        return None
    try:
        result = alert(
            severity="critical",
            component="launchd-crash-loop-watch",
            summary=f"[{display}] launchd health CANNOT BE MEASURED over ssh: "
            f"{_safe_detail(reason)} -- an unreachable host must not read as a clean one",
            details={
                "host": display,
                "reason": reason,
                "evidence_basis": "ssh BatchMode probe from the watching host",
                "remedy": "restore ssh reachability, then confirm its jobs with launchctl list",
            },
            dedupe_key=f"launchd-crash-loop-watch/unreachable/{display}",
            tags=("launchd", "crash-loop", "remote-host"),
        )
    except Exception as exc:
        return {"scope": "alert", "host": display,
                "error": f"{type(exc).__name__}: {_safe_detail(str(exc))}"}
    if result.success:
        return None
    return {"scope": "alert", "host": display,
            "error": f"unreachable-host alert delivery returned unsuccessful: {failure_detail(result)}"}


def _merge_host_reports(
    config: WatchConfig,
    host_runs: Sequence[_HostRun],
    *,
    extra_errors: Sequence[Mapping[str, object]],
    save_error: str | None,
    now: float,
    local_uid: int,
) -> dict[str, object]:
    jobs: list[dict[str, object]] = []
    by_verdict: Counter[str] = Counter()
    crash_looping: list[str] = []
    unknown: list[str] = []
    errors: list[dict[str, object]] = []
    unreachable: list[str] = []
    total = 0
    for run in host_runs:
        summary = run.report.get("summary")
        sm = summary if isinstance(summary, dict) else {}
        total += int(sm.get("total", 0))
        if isinstance(sm.get("by_verdict"), dict):
            by_verdict.update(sm["by_verdict"])
        crash_looping.extend(f"{run.display}/{label}" for label in sm.get("crash_looping", ()))
        unknown.extend(f"{run.display}/{label}" for label in sm.get("unknown", ()))
        for job in run.report.get("jobs") or []:
            if isinstance(job, dict):
                jobs.append({**job, "host": run.display})
        for error in run.report.get("errors") or []:
            if isinstance(error, dict):
                row = dict(error)
                row.setdefault("host", run.display)
                errors.append(row)
        if run.unreachable_reason is not None:
            unreachable.append(run.display)
    errors.extend(dict(e) for e in extra_errors)
    if save_error is not None:
        errors.append({"scope": "state", "error": save_error})
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _iso_timestamp(now),
        "uid": local_uid,
        "policy": _policy_dict(config),
        "hosts": [run.display for run in host_runs],
        "summary": {
            "total": total,
            "by_verdict": dict(sorted(by_verdict.items())),
            "crash_looping": crash_looping,
            "unknown": unknown,
            "unreachable_hosts": unreachable,
            "coverage_complete": not unknown and not errors,
            "error_count": len(errors),
        },
        "jobs": jobs,
        "errors": errors,
    }


def _run_multi_host(config: WatchConfig, *, local_uid: int, now: float) -> tuple[dict[str, object], int]:
    targets: tuple[str | None, ...] = config.hosts if config.remote_only else (None, *config.hosts)
    loaded_state: Mapping[str, object] | None = None
    state_error: str | None = None
    try:
        loaded_state = load_state(config.state_path)
    except HealthStateError as exc:
        state_error = str(exc)

    host_runs: list[_HostRun] = []
    for target in targets:
        prefix = f"{target}/" if target is not None else ""
        host_runs.append(_run_single_host(
            config, host=target, local_uid=local_uid, now=now,
            state=_host_state_slice(loaded_state, prefix=prefix) if loaded_state is not None else None,
            state_error=state_error,
        ))

    extra_errors: list[dict[str, object]] = []
    for run in host_runs:
        if run.unreachable_reason is not None:
            error = _alert_unreachable_host(display=run.display, reason=run.unreachable_reason,
                                            config=config)
            if error is not None:
                extra_errors.append(error)

    merged_jobs: dict[str, object] = {}
    for target, run in zip(targets, host_runs, strict=True):
        prefix = f"{target}/" if target is not None else ""
        run_jobs = run.next_state.get("jobs")
        if not run_jobs and run.discovery_failed and loaded_state is not None:
            # PRESERVE the failed host's evidence. Without this, one failed tick (an ssh flap, a
            # launchctl timeout) deletes that host's evidence at the next save, and a host that
            # drops every other tick can never accumulate threshold non-zero exits.
            prior = _host_state_slice(loaded_state, prefix=prefix)["jobs"]
            run_jobs = prior if prior else run_jobs
        if isinstance(run_jobs, dict):
            for label, entry in run_jobs.items():
                if isinstance(label, str):
                    merged_jobs[prefix + label] = entry
    save_error: str | None = None
    if state_error is None:
        # Never overwrite a state file that could not be loaded: it is evidence, and the
        # replacement would be an empty baseline that quietly restarts every window.
        try:
            save_state(config.state_path, {"schema_version": SCHEMA_VERSION, "jobs": merged_jobs})
        except HealthStateError as exc:
            save_error = str(exc)

    report = _merge_host_reports(config, host_runs, extra_errors=extra_errors,
                                 save_error=save_error, now=now, local_uid=local_uid)
    codes = [run.exit_code for run in host_runs]
    if save_error is not None or extra_errors:
        codes.append(EXIT_UNKNOWN)
    # UNKNOWN dominates: an unmeasurable host is the louder condition and must not read as 1.
    if EXIT_UNKNOWN in codes:
        return report, EXIT_UNKNOWN
    return report, max(codes)


def _evaluate_snapshot(
    snapshot: LaunchdJobSnapshot,
    *,
    prior_entry: dict[str, Any] | None,
    config: WatchConfig,
    now: float,
) -> tuple[EvaluatedJob, dict[str, object], PendingCrashLoopAlert | None]:
    cutoff = now - config.window_seconds
    events = [
        dict(e) for e in (prior_entry or {}).get("nonzero_exit_events", [])
        if isinstance(e, dict) and float(e["observed_at"]) >= cutoff
    ]
    prior_runs_raw = (prior_entry or {}).get("last_runs")
    prior_runs = prior_runs_raw if isinstance(prior_runs_raw, int) else None
    runs_delta = snapshot.runs - prior_runs if prior_runs is not None else None
    counter_reset = runs_delta is not None and runs_delta < 0
    contract_configured = snapshot.label in config.nonzero_findings_labels
    contract_applied = contract_configured and snapshot.periodic
    incident_alerted = bool((prior_entry or {}).get("incident_alerted", False))
    raw_at = (prior_entry or {}).get("incident_alerted_at")
    incident_alerted_at = (
        float(raw_at) if isinstance(raw_at, (int, float)) and not isinstance(raw_at, bool) else None
    )

    if counter_reset:
        events = []
        incident_alerted, incident_alerted_at = False, None
    elif runs_delta is not None and runs_delta > 0:
        if contract_applied:
            events = []
            incident_alerted, incident_alerted_at = False, None
        elif snapshot.last_exit_code is not None and snapshot.last_exit_code > 0:
            events.append({"observed_at": now, "exit_code": snapshot.last_exit_code,
                           "runs_delta": runs_delta, "runs": snapshot.runs})
        else:
            # Exit 0 and signal-based restarts (including a kickstart SIGTERM) end the pattern.
            events = []
            incident_alerted, incident_alerted_at = False, None

    if len(events) < config.threshold:
        incident_alerted, incident_alerted_at = False, None

    event_count = len(events)
    runs_advanced = sum(int(e["runs_delta"]) for e in events)
    latest_exit = int(events[-1]["exit_code"]) if events else None
    verdict, reason = _verdict_for_snapshot(
        snapshot, event_count=event_count, threshold=config.threshold,
        contract_configured=contract_configured, contract_applied=contract_applied,
        counter_reset=counter_reset,
    )
    evidence: dict[str, object] = {
        "total_runs": snapshot.runs,
        "previous_runs": prior_runs,
        "runs_delta": runs_delta,
        "counter_reset": counter_reset,
        "last_terminating_signal": snapshot.last_terminating_signal,
        "observed_nonzero_exit_count": event_count,
        "observed_runs_advanced": runs_advanced,
        "latest_observed_nonzero_exit_code": latest_exit,
        "window_seconds": config.window_seconds,
        "threshold": config.threshold,
        "baseline_established": prior_runs is not None,
        "contract_configured": contract_configured,
        "contract_applied": contract_applied,
        "observations": events,
    }
    next_entry: dict[str, object] = {
        "last_runs": snapshot.runs,
        "last_seen_at": now,
        "nonzero_exit_events": events,
        "incident_alerted": incident_alerted,
        "incident_alerted_at": incident_alerted_at,
    }
    # `incident_alerted` stops the per-tick repeat; `reminder_seconds` stops the SILENCE. A
    # latched incident with no timestamp was written by state that predates reminders: treat it
    # as due rather than as silent forever.
    reminder_due = (
        incident_alerted
        and config.reminder_seconds > 0
        and (incident_alerted_at is None or now - incident_alerted_at >= config.reminder_seconds)
    )
    pending = None
    if verdict == "crash_looping" and (not incident_alerted or reminder_due):
        assert latest_exit is not None
        pending = PendingCrashLoopAlert(label=snapshot.label, exit_code=latest_exit,
                                        count=event_count, window_seconds=config.window_seconds,
                                        runs_advanced=runs_advanced)
    return (
        EvaluatedJob(
            label=snapshot.label, state=snapshot.state, last_exit_code=snapshot.last_exit_code,
            last_exit_raw=snapshot.last_exit_raw, runs=snapshot.runs, pid=snapshot.pid,
            periodic=snapshot.periodic,
            contract="nonzero_on_findings" if contract_applied else "standard",
            verdict=verdict, reason=reason, respawn_restart_evidence=evidence,
        ),
        next_entry,
        pending,
    )


def _verdict_for_snapshot(
    snapshot: LaunchdJobSnapshot,
    *,
    event_count: int,
    threshold: int,
    contract_configured: bool,
    contract_applied: bool,
    counter_reset: bool,
) -> tuple[Verdict, str]:
    if snapshot.runs == 0:
        return "never_run", "launchd reports runs=0 and no bounded failure pattern"
    if contract_applied and snapshot.last_exit_code not in (None, 0):
        return "expected_nonzero", "periodic job is explicitly declared nonzero-on-findings"
    if event_count >= threshold:
        return "crash_looping", f"{event_count} observed non-zero exits reached threshold {threshold}"
    if counter_reset:
        return "observing", "launchd run counter decreased; reboot/reload baseline reset"
    if event_count:
        return "observing", f"{event_count} observed non-zero exits is below threshold {threshold}"
    if contract_configured and not contract_applied:
        return "healthy", "nonzero-on-findings exemption not applied because launchd shows no schedule"
    if snapshot.last_terminating_signal:
        return "healthy", "signal restart is reported as evidence but is not a positive exit-code failure"
    return "healthy", "no repeated positive exit-code pattern in the bounded window"


def _unknown_job(observation: UnknownObservation, *, window_seconds: int) -> EvaluatedJob:
    return EvaluatedJob(
        label=observation.label, state="unknown", last_exit_code=None, last_exit_raw="",
        runs=None, pid=None, periodic=None, contract="unknown", verdict="unknown",
        reason=observation.reason,
        respawn_restart_evidence={
            "total_runs": None, "previous_runs": None, "runs_delta": None,
            "counter_reset": False, "last_terminating_signal": None,
            "observed_nonzero_exit_count": 0, "observed_runs_advanced": 0,
            "latest_observed_nonzero_exit_code": None, "window_seconds": window_seconds,
            "observations": [],
        },
    )


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _validated_state(value: object, *, path: Path | None) -> dict[str, object]:
    source = f"state file {path}" if path is not None else "watcher state"
    if not isinstance(value, dict):
        raise HealthStateError(f"{source} must contain a JSON object")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise HealthStateError(f"{source} has unsupported schema_version {value.get('schema_version')!r}")
    jobs = value.get("jobs")
    if not isinstance(jobs, dict):
        raise HealthStateError(f"{source} jobs must be a JSON object")
    normalized: dict[str, object] = {}
    for label, entry in jobs.items():
        if not isinstance(label, str) or not isinstance(entry, dict):
            raise HealthStateError(f"{source} has an invalid job entry")
        last_runs = entry.get("last_runs")
        if not _is_int(last_runs) or last_runs < 0:
            raise HealthStateError(f"{source} {label!r} has invalid last_runs")
        events = entry.get("nonzero_exit_events")
        if not isinstance(events, list):
            raise HealthStateError(f"{source} {label!r} has invalid nonzero_exit_events")
        clean_events: list[dict[str, object]] = []
        for event in events:
            if not isinstance(event, dict):
                raise HealthStateError(f"{source} {label!r} has a non-object event")
            if not _is_number(event.get("observed_at")):
                raise HealthStateError(f"{source} {label!r} has invalid event observed_at")
            if not _is_int(event.get("exit_code")) or event["exit_code"] <= 0:
                raise HealthStateError(f"{source} {label!r} has invalid event exit_code")
            if not _is_int(event.get("runs_delta")) or event["runs_delta"] <= 0:
                raise HealthStateError(f"{source} {label!r} has invalid event runs_delta")
            if not _is_int(event.get("runs")) or event["runs"] < 0:
                raise HealthStateError(f"{source} {label!r} has invalid event runs")
            clean_events.append({"observed_at": float(event["observed_at"]),
                                 "exit_code": event["exit_code"],
                                 "runs_delta": event["runs_delta"], "runs": event["runs"]})
        incident_alerted = entry.get("incident_alerted", False)
        if not isinstance(incident_alerted, bool):
            raise HealthStateError(f"{source} {label!r} has invalid incident_alerted")
        # Absent means "alerted at an unknown time", which the reminder check reads as due.
        alerted_at = entry.get("incident_alerted_at")
        if alerted_at is not None and not _is_number(alerted_at):
            raise HealthStateError(f"{source} {label!r} has invalid incident_alerted_at")
        last_seen_at = entry.get("last_seen_at", 0.0)
        if not _is_number(last_seen_at):
            raise HealthStateError(f"{source} {label!r} has invalid last_seen_at")
        normalized[label] = {
            "last_runs": last_runs,
            "last_seen_at": float(last_seen_at),
            "nonzero_exit_events": clean_events,
            "incident_alerted": incident_alerted,
            "incident_alerted_at": float(alerted_at) if alerted_at is not None else None,
        }
    return {"schema_version": SCHEMA_VERSION, "jobs": normalized}


def _mark_incident_alerted(state: dict[str, object], label: str, now: float) -> None:
    jobs = state.get("jobs")
    if not isinstance(jobs, dict):
        raise HealthStateError("next watcher state lost its jobs mapping")
    entry = jobs.get(label)
    if not isinstance(entry, dict):
        raise HealthStateError(f"next watcher state lost crash-loop job {label}")
    # Written only on a DELIVERED page, beside the latch it moves with.
    entry["incident_alerted"] = True
    entry["incident_alerted_at"] = now


def _required_nonnegative_int(value: str | None, *, field: str, label: str) -> int:
    parsed = _optional_int(value or "")
    if parsed is None or parsed < 0:
        raise LaunchdParseError(f"{label}: launchctl print has invalid {field}={value!r}")
    return parsed


def _optional_int(value: str) -> int | None:
    normalized = value.strip()
    return int(normalized) if _INTEGER_RE.fullmatch(normalized) else None


def _run_interval(value: str, *, label: str) -> int | None:
    normalized = value.strip()
    if not normalized:
        return None
    suffix = " seconds"
    if not normalized.endswith(suffix):
        raise LaunchdParseError(f"{label}: invalid run interval {normalized!r}")
    return _required_nonnegative_int(normalized[: -len(suffix)], field="run interval", label=label)


def _safe_detail(value: str) -> str:
    return " ".join(value.split())[:500]


def _display_value(value: object) -> str:
    return "-" if value is None or value == "" else str(value)


def _iso_timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, tz=UTC).isoformat().replace("+00:00", "Z")


def _discovery_failure_report(*, config: WatchConfig, uid: int, now: float, reason: str) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _iso_timestamp(now),
        "uid": uid,
        "policy": _policy_dict(config),
        "summary": {
            "total": 0,
            "by_verdict": {},
            "crash_looping": [],
            "unknown": ["<launchd-discovery>"],
            "coverage_complete": False,
            "error_count": 1,
        },
        "jobs": [],
        "errors": [{"scope": "discovery", "error": reason}],
    }


def _parse_args(argv: list[str] | None) -> WatchConfig:
    parser = argparse.ArgumentParser(
        prog="launchd-crash-loop-watch",
        description="Detect repeated non-zero launchd exits. Exit 0 OK, 1 crash loops "
        "(with --fail-on-crash-loop), 3 UNKNOWN.",
    )
    parser.add_argument(
        "--label-prefix", default=os.environ.get(LABEL_PREFIX_ENV),
        help=f"only watch labels starting with this (or set {LABEL_PREFIX_ENV}); required",
    )
    parser.add_argument("--state-file", type=Path, default=DEFAULT_STATE_PATH)
    parser.add_argument("--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS)
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    parser.add_argument(
        "--reminder-seconds", type=int, default=DEFAULT_REMINDER_SECONDS,
        help="re-page a crash loop still running this long after its last delivered page; "
        "0 disables reminders (alert once, then silence for as long as it lasts)",
    )
    parser.add_argument("--launchctl-timeout-seconds", type=float,
                        default=DEFAULT_LAUNCHCTL_TIMEOUT_SECONDS)
    parser.add_argument(
        "--nonzero-findings-label", action="append", default=[], metavar="LABEL",
        help="exact label of a PERIODIC job whose contract uses non-zero exits to report "
        f"findings (repeatable; also {NONZERO_FINDINGS_ENV}, comma-separated)",
    )
    parser.add_argument("--no-alert", action="store_true",
                        help="evaluate and persist evidence without sending pages")
    parser.add_argument("--show-all", action="store_true",
                        help="emit the JSON report and table even when coverage is healthy")
    parser.add_argument("--json", action="store_true",
                        help="always print the JSON report to stdout, and no human table")
    parser.add_argument(
        "--fail-on-crash-loop", action="store_true",
        help="exit 1 for a detected loop; by default a loop that was successfully paged exits 0",
    )
    parser.add_argument(
        "--host", action="append", default=[], metavar="HOST",
        help="also check this ssh destination's launchd jobs (repeatable); an unreachable "
        "host is UNKNOWN and exits 3, never clean",
    )
    parser.add_argument("--remote-only", action="store_true",
                        help="skip the local pass and check only the --host machines")
    args = parser.parse_args(argv)
    if not args.label_prefix:
        raise ValueError(f"--label-prefix (or {LABEL_PREFIX_ENV}) is required")
    labels = set(args.nonzero_findings_label)
    labels.update(x.strip() for x in os.environ.get(NONZERO_FINDINGS_ENV, "").split(",") if x.strip())
    return WatchConfig(
        label_prefix=args.label_prefix,
        state_path=args.state_file,
        window_seconds=args.window_seconds,
        threshold=args.threshold,
        launchctl_timeout_seconds=args.launchctl_timeout_seconds,
        nonzero_findings_labels=frozenset(labels),
        reminder_seconds=args.reminder_seconds,
        no_alert=args.no_alert,
        show_all=args.show_all,
        json_output=args.json,
        fail_on_crash_loop=args.fail_on_crash_loop,
        hosts=tuple(args.host),
        remote_only=args.remote_only,
    )


def main(argv: list[str] | None = None) -> int:
    """Silent on complete healthy coverage unless ``--show-all``."""

    try:
        config = _parse_args(argv)
    except ValueError as exc:
        print(f"launchd-crash-loop-watch: {exc}", file=sys.stderr)
        return EXIT_MISCONFIGURED
    report, exit_code = run_once(config)
    if config.json_output:
        print(json.dumps(report, sort_keys=True, indent=2))
    elif should_emit_report(report, show_all=config.show_all):
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        print(format_human_table(report), file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
