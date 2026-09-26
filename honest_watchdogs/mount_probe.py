"""Probe whether a mounted filesystem is actually serving I/O, with bounded, opt-in remediation.

POSIX (macOS and Linux). The mount table is used only to tell an absent mount from a present
one; it is never accepted as health evidence. A present mount is healthy only after real
filesystem operations complete inside individual hard deadlines:

* ``readdir``: list the mount point;
* ``mkdir_rmdir``: create and remove a uniquely named directory, a bounded WRITE. A listing can
  be answered from a client-side cache while the server is gone; a write has to reach it;
* ``read_known_file`` (optional): read up to 4 KiB of a named file.

Before any of that, a **local positive control** runs the same write probe, through the same
bounded subprocess machinery, against a local directory. If the control cannot complete, the
instrument itself is broken (no subprocesses, full disk, a sandbox), and a mount failure would
be indistinguishable from an instrument failure, so the verdict is UNKNOWN rather than
"unresponsive".

Each probe runs in a fresh interpreter in its own process group and is killed at its deadline:
a thread cannot interrupt a kernel call blocked on a dead network mount, and ``except OSError``
cannot catch a hang.

Exit status: 0 healthy; 1 absent, unresponsive, or remediation failed; 2 misconfigured (the
mount is serving I/O but ``--known-file`` does not exist); 3 UNKNOWN.
"""

from __future__ import annotations

import argparse
import errno as errno_module
import importlib
import json
import os
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn, TextIO

from .exitcodes import EXIT_FINDINGS, EXIT_MISCONFIGURED, EXIT_OK, EXIT_UNKNOWN

SCHEMA_VERSION = 1
MOUNT_POINT_ENV = "WATCHDOG_MOUNT_POINT"
DEFAULT_SCRATCH_SUBPATH = Path(".mount-probe")
DEFAULT_PROBE_TIMEOUT = 8.0
DEFAULT_COMMAND_TIMEOUT = 45.0
DEFAULT_UNMOUNT_COMMAND: tuple[str, ...] = (
    ("/usr/sbin/diskutil", "unmount", "force", "{mount_point}")
    if sys.platform == "darwin"
    else ("umount", "-f", "{mount_point}")
)
MAX_REMEDIATION_ATTEMPTS = 3
MAX_KNOWN_FILE_BYTES = 4096
MAX_CHILD_RESULT_BYTES = 64 * 1024
WORKER_FLAG = "--_mount-probe-worker"

# Names kept for readers of the classification code.
EXIT_HEALTHY = EXIT_OK
EXIT_MOUNT_PROBLEM = EXIT_FINDINGS

ProbeOperation = Callable[..., Mapping[str, Any] | None]
ProbeRunner = Callable[[str, ProbeOperation, tuple[Any, ...], float], "ProbeResult"]
AssessFunction = Callable[[], "Assessment"]


class MountDiscoveryError(RuntimeError):
    """The mount table could not be read reliably."""


@dataclass(frozen=True)
class ProbeError:
    exception: str
    message: str
    errno: int | None = None
    errno_name: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {"exception": self.exception, "errno": self.errno,
                "errno_name": self.errno_name, "message": self.message}


@dataclass(frozen=True)
class ProbeResult:
    name: str
    verdict: str  # ok | error | timeout | unknown | skipped
    elapsed_seconds: float
    details: Mapping[str, Any] = field(default_factory=dict)
    error: ProbeError | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "verdict": self.verdict,
            "elapsed_seconds": round(self.elapsed_seconds, 6),
            "details": dict(self.details),
            "error": self.error.to_json() if self.error is not None else None,
        }


@dataclass(frozen=True)
class Assessment:
    mount_point: Path
    classification: str  # healthy | absent | unresponsive | misconfigured | unknown
    probes: tuple[ProbeResult, ...]

    def to_json(self) -> dict[str, Any]:
        return {"mount_point": str(self.mount_point), "classification": self.classification,
                "probes": [p.to_json() for p in self.probes]}


@dataclass(frozen=True)
class ProbeOperations:
    readdir: ProbeOperation
    mkdir_rmdir: ProbeOperation
    read_known_file: ProbeOperation


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int | None
    elapsed_seconds: float
    stdout: str
    stderr: str
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0 and self.error is None

    def to_json(self) -> dict[str, Any]:
        return {"argv": list(self.argv), "returncode": self.returncode,
                "elapsed_seconds": round(self.elapsed_seconds, 6), "stdout": self.stdout,
                "stderr": self.stderr, "error": self.error}


CommandRunner = Callable[[Sequence[str], float], CommandResult]


@dataclass(frozen=True)
class RemediationConfig:
    mount_point: Path
    mount_command: tuple[str, ...]
    unmount_command: tuple[str, ...] = DEFAULT_UNMOUNT_COMMAND
    recreate_command: tuple[str, ...] | None = None
    attempts: int = 1
    command_timeout: float = DEFAULT_COMMAND_TIMEOUT
    probe_timeout: float = DEFAULT_PROBE_TIMEOUT


@dataclass(frozen=True)
class RemediationResult:
    status: str  # remediated | remediation_failed | not_needed
    message: str
    assessment: Assessment
    attempts: tuple[Mapping[str, Any], ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {"status": self.status, "message": self.message,
                "attempts": [dict(a) for a in self.attempts]}


# --------------------------------------------------------------------------- bounded probes


def _error_from_exception(exc: BaseException) -> ProbeError:
    number = exc.errno if isinstance(exc, OSError) else None
    return ProbeError(
        exception=type(exc).__name__,
        errno=number,
        errno_name=errno_module.errorcode.get(number) if number is not None else None,
        message=str(exc) or repr(exc),
    )


def _encode_child_payload(payload: Mapping[str, Any]) -> bytes:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > MAX_CHILD_RESULT_BYTES:
        raise ValueError("probe result exceeded the child-result size limit")
    return encoded


def _resolve_operation(module_name: str, qualified_name: str) -> ProbeOperation:
    if "<locals>" in qualified_name.split("."):
        raise ValueError("probe operation must be defined at module scope")
    value: Any = importlib.import_module(module_name)
    for component in qualified_name.split("."):
        value = getattr(value, component)
    if not callable(value):
        raise TypeError(f"resolved probe operation is not callable: {qualified_name}")
    return value


def _probe_worker_main(argv: Sequence[str]) -> int:
    """Fresh-interpreter entry point used by :func:`run_bounded_probe`."""

    try:
        if len(argv) != 3:
            raise ValueError("probe worker requires module, qualified name, and JSON args")
        module_name, qualified_name, encoded_args = argv
        raw_args = json.loads(encoded_args)
        if not isinstance(raw_args, list):
            raise ValueError("probe worker arguments must be a JSON list")
        operation = _resolve_operation(module_name, qualified_name)
        try:
            details = operation(*raw_args)
            payload: dict[str, Any] = {"verdict": "ok", "details": dict(details or {}), "error": None}
        except BaseException as exc:
            payload = {"verdict": "error", "details": {}, "error": _error_from_exception(exc).to_json()}
        os.write(sys.stdout.fileno(), _encode_child_payload(payload))
        return 0
    except BaseException as exc:
        print(f"probe worker protocol failure: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 70


def _kill_probe_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        process.kill()
    except ProcessLookupError:
        pass


def run_bounded_probe(
    name: str,
    operation: ProbeOperation,
    args: tuple[Any, ...],
    timeout: float,
) -> ProbeResult:
    """Run a possibly-wedged filesystem operation OUTSIDE this process, with a hard deadline.

    The child is a fresh interpreter in its own process group. It is SIGKILLed at the deadline,
    and the parent never performs an unbounded wait for it, even after the kill: a process in
    uninterruptible sleep on a dead mount may not die promptly.
    """

    started = time.monotonic()
    try:
        module_name = operation.__module__
        qualified_name = operation.__qualname__
        encoded_args = json.dumps(list(args), separators=(",", ":"))
    except (AttributeError, TypeError, ValueError) as exc:
        return ProbeResult(name, "unknown", time.monotonic() - started, error=ProbeError(
            exception="ProbeConfigurationError", message=f"could not serialize probe operation: {exc}"))
    command = (sys.executable, "-m", "honest_watchdogs.mount_probe", WORKER_FLAG,
               module_name, qualified_name, encoded_args)
    # The child must import exactly what the parent can (including a test module's operations).
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, env=env)
    except OSError as exc:
        return ProbeResult(name, "unknown", time.monotonic() - started, error=_error_from_exception(exc))
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - started
        _kill_probe_process(process)
        try:
            process.communicate(timeout=0.05)
        except subprocess.TimeoutExpired:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        return ProbeResult(name, "timeout", elapsed, error=ProbeError(
            exception="TimeoutError", message=f"probe exceeded its {timeout:.3f}s hard timeout"))

    elapsed = time.monotonic() - started
    if not stdout or b"\n" not in stdout:
        diagnostic = stderr.decode("utf-8", errors="replace").strip()
        return ProbeResult(name, "unknown", elapsed, error=ProbeError(
            exception="ProbeProcessError",
            message=f"probe worker exited {process.returncode} without a complete result"
            f"{f': {diagnostic}' if diagnostic else ''}"))
    if len(stdout) > MAX_CHILD_RESULT_BYTES:
        return ProbeResult(name, "unknown", elapsed, error=ProbeError(
            exception="ProbeProtocolError", message="probe worker result exceeded the size limit"))
    try:
        decoded = json.loads(stdout.split(b"\n", 1)[0])
        verdict = str(decoded["verdict"])
        details = decoded.get("details")
        raw_error = decoded.get("error")
        if verdict not in {"ok", "error"} or not isinstance(details, dict):
            raise ValueError("invalid probe result fields")
        error = None
        if raw_error is not None:
            if not isinstance(raw_error, dict):
                raise ValueError("invalid probe error")
            error = ProbeError(
                exception=str(raw_error.get("exception") or "Exception"),
                errno=raw_error.get("errno") if isinstance(raw_error.get("errno"), int) else None,
                errno_name=str(raw_error["errno_name"]) if raw_error.get("errno_name") is not None else None,
                message=str(raw_error.get("message") or "no diagnostic"),
            )
        return ProbeResult(name, verdict, elapsed, details=details, error=error)
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        return ProbeResult(name, "unknown", elapsed, error=ProbeError(
            exception="ProbeProtocolError", message=f"could not decode probe worker result: {exc}"))


# --------------------------------------------------------------------------- mount discovery


def _decode_mount_path(value: str) -> str:
    for encoded, decoded in (("\\040", " "), ("\\011", "\t"), ("\\134", "\\")):
        value = value.replace(encoded, decoded)
    return value


def _normal_mount_path(path: str | Path) -> str:
    normalized = os.path.abspath(os.fspath(path))
    return normalized if normalized == os.sep else normalized.rstrip(os.sep)


def _entry_from_mountinfo(text: str, target: str) -> str | None:
    if not text.strip():
        raise MountDiscoveryError("/proc/self/mountinfo was empty")
    for line in text.splitlines():
        fields = line.split()
        if "-" not in fields or len(fields) < 6:
            raise MountDiscoveryError(f"malformed mountinfo row: {line!r}")
        if _normal_mount_path(_decode_mount_path(fields[4])) == target:
            return line
    return None


def _entry_from_mount_command(text: str, target: str) -> str | None:
    if not text.strip():
        raise MountDiscoveryError("mount command returned an empty mount table")
    for line in text.splitlines():
        prefix, separator, _options = line.rpartition(" (")
        _device, on_separator, mount_path = prefix.rpartition(" on ")
        if not separator or not on_separator or not mount_path:
            raise MountDiscoveryError(f"malformed mount output row: {line!r}")
        if _normal_mount_path(_decode_mount_path(mount_path)) == target:
            return line
    return None


def _mount_entry_operation(mount_point: str, source: str, mount_command: str | None,
                           mountinfo_path: str) -> Mapping[str, Any]:
    target = _normal_mount_path(mount_point)
    if source == "mountinfo":
        with open(mountinfo_path, encoding="utf-8") as stream:
            entry = _entry_from_mountinfo(stream.read(), target)
        source_name = mountinfo_path
    elif source == "command":
        command = mount_command or shutil.which("mount")
        if command is None:
            raise MountDiscoveryError("could not locate the mount command")
        completed = subprocess.run([command], check=False, capture_output=True, text=True)
        if completed.returncode != 0:
            diagnostic = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic"
            raise MountDiscoveryError(f"{command} exited {completed.returncode}: {diagnostic}")
        entry = _entry_from_mount_command(completed.stdout, target)
        source_name = command
    else:
        raise MountDiscoveryError(f"unsupported mount discovery source: {source}")
    return {"present": entry is not None, "source": source_name, "entry": entry}


def detect_mount_entry(
    mount_point: Path,
    timeout: float,
    *,
    runner: ProbeRunner = run_bounded_probe,
    source: str | None = None,
    mount_command: str | None = None,
    mountinfo_path: Path = Path("/proc/self/mountinfo"),
) -> ProbeResult:
    if source is None:
        source = "mountinfo" if mountinfo_path.is_file() else "command"
    command = mount_command
    if source == "command" and command is None:
        command = "/sbin/mount" if Path("/sbin/mount").is_file() else shutil.which("mount")
    return runner("mount_entry", _mount_entry_operation,
                  (str(mount_point), source, command, str(mountinfo_path)), timeout)


# --------------------------------------------------------------------------- I/O probes


def _probe_readdir(mount_point: str) -> Mapping[str, Any]:
    with os.scandir(mount_point) as entries:
        entry_observed = next(entries, None) is not None
    return {"entry_observed": entry_observed}


def _probe_mkdir_rmdir(mount_point: str, scratch_subpath: str) -> Mapping[str, Any]:
    base = Path(mount_point) / scratch_subpath
    candidate = base.with_name(f"{base.name}.{os.getpid()}.{uuid.uuid4().hex}")
    created = False
    try:
        os.mkdir(candidate, mode=0o700)
        created = True
    finally:
        if created:
            os.rmdir(candidate)
    return {"created_and_removed": str(candidate)}


def _probe_read_known_file(mount_point: str, known_file: str) -> Mapping[str, Any]:
    with (Path(mount_point) / known_file).open("rb", buffering=0) as stream:
        content = stream.read(MAX_KNOWN_FILE_BYTES)
    return {"path": known_file, "bytes_read": len(content)}


DEFAULT_OPERATIONS = ProbeOperations(
    readdir=_probe_readdir,
    mkdir_rmdir=_probe_mkdir_rmdir,
    read_known_file=_probe_read_known_file,
)

_IO_PROBES = ("readdir", "mkdir_rmdir", "read_known_file")


def _skipped(name: str, reason: str) -> ProbeResult:
    return ProbeResult(name, "skipped", 0.0, details={"reason": reason})


def _mount_present(result: ProbeResult) -> bool | None:
    if result.verdict != "ok":
        return None
    present = result.details.get("present")
    return present if isinstance(present, bool) else None


def assess_mount(
    mount_point: Path,
    *,
    scratch_subpath: Path = DEFAULT_SCRATCH_SUBPATH,
    known_file: Path | None = None,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
    read_only: bool = False,
    control_dir: Path | None = None,
    runner: ProbeRunner = run_bounded_probe,
    operations: ProbeOperations = DEFAULT_OPERATIONS,
    mount_entry_result: ProbeResult | None = None,
) -> Assessment:
    """Classify one mount.

    ``control_dir``: when given, the write probe first runs against this LOCAL directory through
    the same runner. A failed control makes the verdict UNKNOWN: the instrument has not shown it
    can observe a healthy write, so it cannot report an unhealthy one.
    """

    mount_point = Path(_normal_mount_path(mount_point))
    results: list[ProbeResult] = []

    if control_dir is not None:
        control = runner("local_control", operations.mkdir_rmdir,
                         (str(control_dir), str(scratch_subpath)), timeout)
        results.append(control)
        if control.verdict != "ok":
            reason = "not run because the local positive control failed"
            results.extend(_skipped(n, reason) for n in ("mount_entry", *_IO_PROBES))
            return Assessment(mount_point, "unknown", tuple(results))

    mount_result = mount_entry_result or detect_mount_entry(mount_point, timeout, runner=runner)
    results.append(mount_result)
    present = _mount_present(mount_result)
    if present is None:
        results.extend(_skipped(n, "not run because mount presence is unknown") for n in _IO_PROBES)
        return Assessment(mount_point, "unknown", tuple(results))
    if not present:
        results.extend(_skipped(n, "not run because no mount-table entry is present")
                       for n in _IO_PROBES)
        return Assessment(mount_point, "absent", tuple(results))

    results.append(runner("readdir", operations.readdir, (str(mount_point),), timeout))
    if read_only:
        results.append(_skipped("mkdir_rmdir", "disabled by --read-only"))
    else:
        results.append(runner("mkdir_rmdir", operations.mkdir_rmdir,
                              (str(mount_point), str(scratch_subpath)), timeout))
    if known_file is None:
        results.append(_skipped("read_known_file", "no --known-file was supplied"))
    else:
        results.append(runner("read_known_file", operations.read_known_file,
                              (str(mount_point), str(known_file)), timeout))

    io = [r for r in results if r.name in _IO_PROBES]
    if _is_known_file_enoent_only(io):
        # A filesystem that answers ENOENT inside the deadline, while readdir and the write
        # both pass, has demonstrated it is serving I/O. Calling that "unresponsive" would
        # contradict the probes it is drawn from, and "unresponsive" arms the force-unmount
        # path: a renamed file could tear down a healthy mount.
        classification = "misconfigured"
    elif any(r.verdict in {"error", "timeout"} for r in io):
        classification = "unresponsive"
    elif any(r.verdict == "unknown" for r in io):
        classification = "unknown"
    elif io[0].verdict != "ok":
        classification = "unknown"
    else:
        classification = "healthy"
    return Assessment(mount_point, classification, tuple(results))


def _is_known_file_enoent_only(io_results: Sequence[ProbeResult]) -> bool:
    """True when the only failing I/O probe is read_known_file reporting ENOENT."""

    known = next((r for r in io_results if r.name == "read_known_file"), None)
    if known is None or known.verdict != "error":
        return False
    if known.error is None or known.error.errno != errno_module.ENOENT:
        return False
    return all(r.verdict in {"ok", "skipped"} for r in io_results if r.name != "read_known_file")


# --------------------------------------------------------------------------- remediation


def run_command(argv: Sequence[str], timeout: float) -> CommandResult:
    started = time.monotonic()
    command = tuple(argv)
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True,
                                   timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(command, None, time.monotonic() - started,
                             stdout=exc.stdout if isinstance(exc.stdout, str) else "",
                             stderr=exc.stderr if isinstance(exc.stderr, str) else "",
                             error=f"command exceeded {timeout:.3f}s timeout")
    except OSError as exc:
        return CommandResult(command, None, time.monotonic() - started, stdout="", stderr="",
                             error=f"{type(exc).__name__}: {exc}")
    return CommandResult(command, completed.returncode, time.monotonic() - started,
                         stdout=completed.stdout.strip(), stderr=completed.stderr.strip())


def _expand_command(command: Sequence[str], mount_point: Path) -> tuple[str, ...]:
    return tuple(part.replace("{mount_point}", str(mount_point)) for part in command)


def _probe_recreation_access(parent: str) -> Mapping[str, Any]:
    candidate = Path(parent) / f".mount-probe-preflight.{os.getpid()}.{uuid.uuid4().hex}"
    created = False
    try:
        os.mkdir(candidate, mode=0o700)
        created = True
    finally:
        if created:
            os.rmdir(candidate)
    return {"created_and_removed": str(candidate)}


def _mountpoint_kind(path: Path) -> str:
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return "missing"
    except OSError as exc:
        return f"error:{type(exc).__name__}: {exc}"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def _ensure_mountpoint(config: RemediationConfig, command_runner: CommandRunner) -> tuple[bool, Mapping[str, Any]]:
    """Some unmount tools delete the mount-point directory; put it back, or fail loudly."""

    kind = _mountpoint_kind(config.mount_point)
    if kind == "directory":
        return True, {"status": "present", "path": str(config.mount_point)}
    if kind != "missing":
        return False, {"status": "failed", "path": str(config.mount_point),
                       "error": f"mount point is not a directory ({kind})"}
    try:
        os.mkdir(config.mount_point, mode=0o755)
    except OSError as exc:
        direct_error = _error_from_exception(exc).to_json()
    else:
        return True, {"status": "recreated_directly", "path": str(config.mount_point)}
    if config.recreate_command is None:
        return False, {"status": "failed", "path": str(config.mount_point),
                       "error": "unmount removed the mount point and direct recreation failed; "
                                "a privileged --recreate-command may be required",
                       "direct_error": direct_error}
    outcome = command_runner(_expand_command(config.recreate_command, config.mount_point),
                             config.command_timeout)
    kind_after = _mountpoint_kind(config.mount_point)
    if not outcome.succeeded or kind_after != "directory":
        return False, {"status": "failed", "path": str(config.mount_point),
                       "error": "privileged mount-point recreation did not leave a directory "
                                f"(observed {kind_after})",
                       "direct_error": direct_error, "command": outcome.to_json()}
    return True, {"status": "recreated_by_command", "path": str(config.mount_point),
                  "direct_error": direct_error, "command": outcome.to_json()}


def remediate(
    initial: Assessment,
    config: RemediationConfig,
    reassess: AssessFunction,
    *,
    command_runner: CommandRunner = run_command,
) -> RemediationResult:
    """Try a bounded recovery, re-checking before every destructive step, recording everything."""

    if not config.mount_command:
        return RemediationResult("remediation_failed",
                                 "--remediate requires a non-empty --mount-command; no action was taken",
                                 initial)
    if initial.classification not in {"absent", "unresponsive"}:
        return RemediationResult("not_needed",
                                 f"classification is {initial.classification}; no remediation was attempted",
                                 initial)

    records: list[Mapping[str, Any]] = []
    latest = initial
    for attempt in range(1, config.attempts + 1):
        # This re-check narrows, but cannot eliminate, the check/action race.
        latest = reassess()
        record: dict[str, Any] = {"attempt": attempt, "pre_action_assessment": latest.to_json(),
                                  "actions": []}
        actions: list[Any] = record["actions"]
        if latest.classification == "healthy":
            records.append(record)
            return RemediationResult("remediated",
                                     "mount became healthy before a remediation action was needed",
                                     latest, tuple(records))
        if latest.classification not in {"absent", "unresponsive"}:
            records.append(record)
            return RemediationResult("remediation_failed",
                                     f"fresh pre-action probe was {latest.classification}; "
                                     "refusing a destructive action",
                                     latest, tuple(records))

        if latest.classification == "unresponsive":
            preflight = run_bounded_probe("mountpoint_recreation_preflight", _probe_recreation_access,
                                          (str(config.mount_point.parent),), config.probe_timeout)
            actions.append({"kind": "mountpoint_recreation_preflight", **preflight.to_json()})
            if preflight.verdict != "ok" and config.recreate_command is None:
                records.append(record)
                return RemediationResult(
                    "remediation_failed",
                    "refusing to unmount: the mount point may be deleted and this process could "
                    "not prove it can recreate it; configure a privileged --recreate-command",
                    latest, tuple(records))
            unmount = command_runner(_expand_command(config.unmount_command, config.mount_point),
                                     config.command_timeout)
            actions.append({"kind": "unmount", **unmount.to_json()})
            if not unmount.succeeded:
                records.append(record)
                continue

        ready, evidence = _ensure_mountpoint(config, command_runner)
        actions.append({"kind": "ensure_mountpoint", **evidence})
        if not ready:
            records.append(record)
            return RemediationResult(
                "remediation_failed",
                "mount point is absent and could not be recreated; the host may require a "
                "privileged mkdir/chown repair",
                latest, tuple(records))

        mount = command_runner(_expand_command(config.mount_command, config.mount_point),
                               config.command_timeout)
        actions.append({"kind": "mount", **mount.to_json()})
        if not mount.succeeded:
            records.append(record)
            continue

        latest = reassess()
        record["post_action_assessment"] = latest.to_json()
        records.append(record)
        if latest.classification == "healthy":
            return RemediationResult("remediated",
                                     f"mount passed I/O probes after remediation attempt {attempt}",
                                     latest, tuple(records))
        if latest.classification == "unknown":
            return RemediationResult("remediation_failed",
                                     "post-remediation probe was unknown; refusing further destructive retries",
                                     latest, tuple(records))

    return RemediationResult(
        "remediation_failed",
        f"mount did not become healthy after {config.attempts} bounded remediation attempt(s); "
        "host-level recovery such as a reboot may be required",
        latest, tuple(records))


# --------------------------------------------------------------------------- reporting


def probe_coverage() -> dict[str, Any]:
    """What this run actually tested, and therefore what it cannot say.

    Every probe runs under ONE interpreter binary. On macOS, privacy permissions (TCC, "Full
    Disk Access") are granted per binary, so a healthy verdict here says nothing about whether a
    different binary (another Python, node, a shell under launchd) can read the same mount. One
    ungranted binary fails instantly with EPERM; another can block in ``open()`` indefinitely.
    The report names its scope so a scoped pass is not read as a general one.
    """

    executable = Path(sys.executable)
    try:
        resolved = str(executable.resolve())
    except OSError:
        resolved = str(executable)
    return {
        "tested_binary": resolved,
        "tested_binary_is_symlink": executable.is_symlink(),
        "scope": "one binary",
        "not_surveyed": (
            "NOT SURVEYED: every other binary. Where filesystem permissions are granted "
            "PER-BINARY (for example macOS privacy controls), this verdict covers only the "
            "interpreter above. A healthy result here is NOT evidence that other programs on "
            "this host can use the mount."
        ),
    }


def build_report(initial: Assessment, remediation: RemediationResult | None = None) -> dict[str, Any]:
    assessment = remediation.assessment if remediation is not None else initial
    status = ("remediation_failed" if remediation is not None and remediation.status == "remediation_failed"
              else assessment.classification)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        **assessment.to_json(),
        "initial_classification": initial.classification,
        "remediation": remediation.to_json() if remediation is not None
        else {"status": "not_requested", "message": "report-only mode"},
    }
    if remediation is not None:
        report["initial_assessment"] = initial.to_json()
    report["coverage"] = probe_coverage()
    return report


def _evidence_text(assessment: Assessment) -> str:
    if assessment.classification == "absent":
        mount_probe = next(p for p in assessment.probes if p.name == "mount_entry")
        return f"mount_entry:absent:elapsed={mount_probe.elapsed_seconds:.3f}s"
    evidence: list[str] = []
    for probe in assessment.probes:
        if probe.verdict not in {"error", "timeout", "unknown"}:
            continue
        error = probe.error
        exception = error.exception if error is not None else "no-exception"
        errno_text = f":errno={error.errno_name or error.errno}" if error and error.errno is not None else ""
        evidence.append(f"{probe.name}:{probe.verdict}:{exception}{errno_text}:"
                        f"elapsed={probe.elapsed_seconds:.3f}s")
    return ",".join(evidence) if evidence else "all-enabled-io-probes:ok"


def render_human(report: Mapping[str, Any], assessment: Assessment) -> str:
    remediation = report.get("remediation")
    status = remediation.get("status") if isinstance(remediation, Mapping) else "unknown"
    return (
        f"MOUNT_PROBE status={report['status']} classification={assessment.classification} "
        f"mount_point={assessment.mount_point} evidence={_evidence_text(assessment)} "
        f"remediation={status} "
        f"tested_binary={(report.get('coverage') or {}).get('tested_binary', 'unknown')} "
        f"coverage=one-binary-only"
    )


def exit_code_for_report(report: Mapping[str, Any]) -> int:
    if report.get("status") == "remediation_failed":
        return EXIT_FINDINGS
    classification = report.get("classification")
    if classification == "healthy":
        return EXIT_OK
    if classification in {"absent", "unresponsive"}:
        return EXIT_FINDINGS
    if classification == "misconfigured":
        return EXIT_MISCONFIGURED
    return EXIT_UNKNOWN


# --------------------------------------------------------------------------- CLI


def _relative_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or path in {Path("."), Path("")}:
        raise argparse.ArgumentTypeError("must be a non-empty relative path")
    if ".." in path.parts:
        raise argparse.ArgumentTypeError("must not contain '..'")
    return path


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not 0 < parsed <= 300:
        raise argparse.ArgumentTypeError("must be greater than 0 and at most 300 seconds")
    return parsed


def _attempt_count(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= parsed <= MAX_REMEDIATION_ATTEMPTS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_REMEDIATION_ATTEMPTS}")
    return parsed


def _command(value: str) -> tuple[str, ...]:
    try:
        parsed = tuple(shlex.split(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"could not parse command: {exc}") from exc
    if not parsed:
        raise argparse.ArgumentTypeError("must not be empty")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mount-probe",
        description="Probe real I/O on a mounted filesystem; emit one JSON line and one human line.",
    )
    parser.add_argument("--mount-point", type=Path, default=os.environ.get(MOUNT_POINT_ENV),
                        help=f"mount point to probe (or set {MOUNT_POINT_ENV}); required")
    parser.add_argument("--scratch-subpath", type=_relative_path, default=DEFAULT_SCRATCH_SUBPATH,
                        help="relative name prefix for the temporary mkdir/rmdir probe")
    parser.add_argument("--known-file", type=_relative_path,
                        help=f"relative file to read (at most {MAX_KNOWN_FILE_BYTES} bytes)")
    parser.add_argument("--timeout", type=_positive_float, default=DEFAULT_PROBE_TIMEOUT,
                        help=f"hard timeout per probe (default {DEFAULT_PROBE_TIMEOUT:g}s)")
    parser.add_argument("--read-only", action="store_true",
                        help="skip the write probe; the report records the reduced coverage")
    parser.add_argument("--control-dir", type=Path, default=Path(tempfile.gettempdir()),
                        help="local directory for the positive-control write (default: the "
                        "system temp directory)")
    parser.add_argument("--no-control", action="store_true",
                        help="skip the local positive control")
    parser.add_argument("--json", action="store_true",
                        help="print only the JSON report line, without the human line")
    parser.add_argument("--remediate", action="store_true",
                        help="opt in to bounded unmount/mount recovery; off by default")
    parser.add_argument("--mount-command", type=_command,
                        help="command used to mount; parsed without a shell; may contain {mount_point}")
    parser.add_argument("--unmount-command", type=_command, default=DEFAULT_UNMOUNT_COMMAND,
                        help="command used for an unresponsive mount (default: "
                        f"'{' '.join(DEFAULT_UNMOUNT_COMMAND)}')")
    parser.add_argument("--recreate-command", type=_command,
                        help="privileged helper, used only if unmount removes the mount point and "
                        "a direct mkdir fails; may contain {mount_point}")
    parser.add_argument("--remediation-attempts", type=_attempt_count, default=1)
    parser.add_argument("--command-timeout", type=_positive_float, default=DEFAULT_COMMAND_TIMEOUT)
    return parser


def _configuration_error(message: str, output: TextIO, *, json_only: bool = False) -> NoReturn:
    coverage = probe_coverage()
    print(json.dumps({"schema_version": SCHEMA_VERSION, "status": "misconfigured",
                      "classification": "unknown", "error": message, "coverage": coverage},
                     sort_keys=True), file=output)
    if not json_only:
        print(f"MOUNT_PROBE status=misconfigured evidence={message} "
              f"tested_binary={coverage['tested_binary']} coverage=one-binary-only", file=output)
    raise SystemExit(EXIT_MISCONFIGURED)


def main(argv: Sequence[str] | None = None, *, output: TextIO = sys.stdout) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        if args.mount_point is None:
            _configuration_error(f"--mount-point (or {MOUNT_POINT_ENV}) is required", output, json_only=args.json)
        if args.remediate and args.read_only:
            _configuration_error("--remediate cannot be combined with --read-only", output, json_only=args.json)
        if args.remediate and args.mount_command is None:
            _configuration_error("--remediate requires --mount-command", output, json_only=args.json)
    except SystemExit as exc:
        return int(exc.code or 0)

    control_dir = None if args.no_control else args.control_dir

    def assess() -> Assessment:
        return assess_mount(Path(args.mount_point), scratch_subpath=args.scratch_subpath,
                            known_file=args.known_file, timeout=args.timeout,
                            read_only=args.read_only, control_dir=control_dir)

    initial = assess()
    remediation: RemediationResult | None = None
    if args.remediate:
        remediation = remediate(initial, RemediationConfig(
            mount_point=Path(_normal_mount_path(args.mount_point)),
            mount_command=args.mount_command,
            unmount_command=args.unmount_command,
            recreate_command=args.recreate_command,
            attempts=args.remediation_attempts,
            command_timeout=args.command_timeout,
            probe_timeout=args.timeout,
        ), assess)
    report = build_report(initial, remediation)
    final = remediation.assessment if remediation else initial
    print(json.dumps(report, sort_keys=True), file=output)
    if not args.json:
        print(render_human(report, final), file=output)
    return exit_code_for_report(report)


if __name__ == "__main__":
    if sys.argv[1:2] == [WORKER_FLAG]:
        raise SystemExit(_probe_worker_main(sys.argv[2:]))
    raise SystemExit(main())
