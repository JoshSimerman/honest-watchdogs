"""Tests for the mount probe.

Most probes run for real, in real subprocesses, against real temp directories: the point of the
tool is a hard deadline around a blocking syscall, and a stub cannot block. Test-module
operations (a readdir that sleeps, one that crashes the worker) are passed through the same
fresh-interpreter machinery the real probes use.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from honest_watchdogs import mount_probe as health


def present_mount_result() -> health.ProbeResult:
    return health.ProbeResult(
        "mount_entry",
        "ok",
        0.001,
        details={"present": True, "source": "test seam", "entry": "present"},
    )


def assessment(classification: str, mount_point: Path) -> health.Assessment:
    present = classification != "absent"
    mount_result = health.ProbeResult(
        "mount_entry",
        "ok",
        0.001,
        details={"present": present, "source": "test seam", "entry": "present"},
    )
    probe_verdict = "ok" if classification == "healthy" else "timeout"
    io_probe = health.ProbeResult(
        "readdir",
        probe_verdict,
        0.01,
        error=(
            None
            if probe_verdict == "ok"
            else health.ProbeError("TimeoutError", "fixture timeout")
        ),
    )
    return health.Assessment(mount_point, classification, (mount_result, io_probe))


def blocking_readdir(_mount_point: str) -> Mapping[str, Any]:
    time.sleep(10)
    return {"unexpected": "completed"}


def slow_readdir(mount_point: str) -> Mapping[str, Any]:
    time.sleep(0.08)
    with os.scandir(mount_point) as entries:
        return {"entry_observed": next(entries, None) is not None}


def crashing_readdir(_mount_point: str) -> Mapping[str, Any]:
    os._exit(17)


def blocking_write(_mount_point: str, _scratch: str) -> Mapping[str, Any]:
    time.sleep(10)
    return {"unexpected": "completed"}


class RecordingCommandRunner:
    def __init__(self, callback: Any | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.callback = callback

    def __call__(self, argv: Sequence[str], _timeout: float) -> health.CommandResult:
        command = tuple(argv)
        self.calls.append(command)
        if self.callback is not None:
            self.callback(command)
        return health.CommandResult(command, 0, 0.001, "", "")


def sequence_assessor(*values: health.Assessment) -> health.AssessFunction:
    remaining = iter(values)

    def assess_next() -> health.Assessment:
        return next(remaining)

    return assess_next


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "honest_watchdogs.mount_probe", *args],
        check=False,
        capture_output=True,
        text=True,
    )


def cli_report(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    first_line = result.stdout.splitlines()[0]
    report = json.loads(first_line)
    assert isinstance(report, dict)
    return report


def test_healthy_real_directory_runs_readdir_write_and_known_file(tmp_path: Path) -> None:
    (tmp_path / "known.txt").write_bytes(b"known-good\n")

    result = health.assess_mount(
        tmp_path,
        known_file=Path("known.txt"),
        timeout=1.0,
        mount_entry_result=present_mount_result(),
    )

    assert result.classification == "healthy", (
        f"responsive filesystem was classified as {result.classification}"
    )
    assert {probe.name: probe.verdict for probe in result.probes} == {
        "mount_entry": "ok",
        "readdir": "ok",
        "mkdir_rmdir": "ok",
        "read_known_file": "ok",
    }
    write_probe = next(probe for probe in result.probes if probe.name == "mkdir_rmdir")
    assert not Path(str(write_probe.details["created_and_removed"])).exists()


def test_present_mount_with_blocked_readdir_is_unresponsive_not_healthy(
    tmp_path: Path,
) -> None:
    operations = health.ProbeOperations(
        readdir=blocking_readdir,
        mkdir_rmdir=health.DEFAULT_OPERATIONS.mkdir_rmdir,
        read_known_file=health.DEFAULT_OPERATIONS.read_known_file,
    )

    started = time.monotonic()
    result = health.assess_mount(
        tmp_path,
        timeout=0.08,
        operations=operations,
        mount_entry_result=present_mount_result(),
    )
    wall_time = time.monotonic() - started

    assert result.classification == "unresponsive", (
        "present mount with timed-out readdir must be classified unresponsive, "
        f"not {result.classification}"
    )
    readdir = next(probe for probe in result.probes if probe.name == "readdir")
    assert readdir.verdict == "timeout"
    assert readdir.error is not None
    assert readdir.error.exception == "TimeoutError"
    assert 0.05 <= readdir.elapsed_seconds < 0.5
    assert wall_time < 1.0, "blocked readdir escaped its hard timeout"


def test_slow_but_working_readdir_has_timeout_headroom(tmp_path: Path) -> None:
    operations = health.ProbeOperations(
        readdir=slow_readdir,
        mkdir_rmdir=health.DEFAULT_OPERATIONS.mkdir_rmdir,
        read_known_file=health.DEFAULT_OPERATIONS.read_known_file,
    )

    result = health.assess_mount(
        tmp_path,
        timeout=0.5,
        operations=operations,
        mount_entry_result=present_mount_result(),
    )

    assert result.classification == "healthy", (
        f"slow operation inside its deadline was classified {result.classification}"
    )
    readdir = next(probe for probe in result.probes if probe.name == "readdir")
    assert readdir.elapsed_seconds >= 0.06
    assert readdir.verdict == "ok"


def test_real_non_mount_directory_is_absent_and_io_is_not_attempted(tmp_path: Path) -> None:
    result = health.assess_mount(tmp_path, timeout=1.0)

    assert result.classification == "absent", (
        f"ordinary directory without a mount entry was classified {result.classification}"
    )
    mount_probe = result.probes[0]
    assert mount_probe.name == "mount_entry"
    assert mount_probe.verdict == "ok"
    assert mount_probe.details["present"] is False
    assert all(probe.verdict == "skipped" for probe in result.probes[1:])


def test_missing_mount_discovery_source_is_unknown_never_healthy(tmp_path: Path) -> None:
    mount_result = health.detect_mount_entry(
        tmp_path,
        0.5,
        source="command",
        mount_command=str(tmp_path / "missing-mount-command"),
    )

    result = health.assess_mount(
        tmp_path,
        timeout=0.5,
        mount_entry_result=mount_result,
    )

    assert result.classification == "unknown", (
        "missing mount discovery source must be unknown, "
        f"not {result.classification}"
    )
    assert result.probes[0].verdict == "error"
    assert result.probes[0].error is not None
    assert result.probes[0].error.exception == "FileNotFoundError"
    assert health.exit_code_for_report(health.build_report(result)) == health.EXIT_UNKNOWN


def test_empty_mount_discovery_source_is_unknown_never_clean(tmp_path: Path) -> None:
    empty_mountinfo = tmp_path / "mountinfo"
    empty_mountinfo.write_text("", encoding="utf-8")

    mount_result = health.detect_mount_entry(
        tmp_path,
        0.5,
        source="mountinfo",
        mountinfo_path=empty_mountinfo,
    )

    result = health.assess_mount(
        tmp_path,
        timeout=0.5,
        mount_entry_result=mount_result,
    )
    assert result.classification == "unknown", (
        "empty mount discovery source must fail loud as unknown, "
        f"not {result.classification}"
    )
    assert mount_result.verdict == "error"
    assert mount_result.error is not None
    assert mount_result.error.exception == "MountDiscoveryError"
    assert "was empty" in mount_result.error.message


def test_unreadable_mount_discovery_source_is_unknown_never_clean(tmp_path: Path) -> None:
    unreadable_mountinfo = tmp_path / "mountinfo"
    unreadable_mountinfo.write_text("fixture\n", encoding="utf-8")
    unreadable_mountinfo.chmod(0)
    try:
        mount_result = health.detect_mount_entry(
            tmp_path,
            0.5,
            source="mountinfo",
            mountinfo_path=unreadable_mountinfo,
        )
    finally:
        unreadable_mountinfo.chmod(0o600)

    result = health.assess_mount(
        tmp_path,
        timeout=0.5,
        mount_entry_result=mount_result,
    )
    assert result.classification == "unknown", (
        "unreadable mount discovery source must fail loud as unknown, "
        f"not {result.classification}"
    )
    assert mount_result.verdict == "error"
    assert mount_result.error is not None
    assert mount_result.error.exception == "PermissionError"
    assert mount_result.error.errno_name == "EACCES"


def test_probe_worker_crash_is_unknown_never_healthy(tmp_path: Path) -> None:
    operations = health.ProbeOperations(
        readdir=crashing_readdir,
        mkdir_rmdir=health.DEFAULT_OPERATIONS.mkdir_rmdir,
        read_known_file=health.DEFAULT_OPERATIONS.read_known_file,
    )

    result = health.assess_mount(
        tmp_path,
        timeout=0.5,
        operations=operations,
        mount_entry_result=present_mount_result(),
    )

    assert result.classification == "unknown", (
        f"probe worker crash must be unknown, not {result.classification}"
    )
    readdir = next(probe for probe in result.probes if probe.name == "readdir")
    assert readdir.verdict == "unknown"
    assert readdir.error is not None
    assert readdir.error.exception == "ProbeProcessError"


def test_known_file_error_names_probe_errno_and_elapsed_time(tmp_path: Path) -> None:
    result = health.assess_mount(
        tmp_path,
        known_file=Path("missing-known-file"),
        timeout=1.0,
        mount_entry_result=present_mount_result(),
    )

    assert result.classification == "misconfigured"
    read_probe = next(probe for probe in result.probes if probe.name == "read_known_file")
    assert read_probe.verdict == "error"
    assert read_probe.elapsed_seconds >= 0
    assert read_probe.error is not None
    assert read_probe.error.errno == 2
    assert read_probe.error.errno_name == "ENOENT"
    assert read_probe.error.exception == "FileNotFoundError"


def test_cli_absent_effect_includes_json_human_evidence_and_exit_code(tmp_path: Path) -> None:
    result = run_cli(
        "--mount-point",
        str(tmp_path),
        "--read-only",
        "--timeout",
        "1",
    )

    report = cli_report(result)
    assert result.returncode == health.EXIT_MOUNT_PROBLEM
    assert report["classification"] == "absent"
    assert report["status"] == "absent"
    probes = [probe["name"] for probe in report["probes"]]
    assert probes[:2] == ["local_control", "mount_entry"]
    assert "MOUNT_PROBE status=absent" in result.stdout.splitlines()[1]
    assert "mount_entry:absent:elapsed=" in result.stdout.splitlines()[1]


def test_cli_healthy_root_read_only_is_zero_and_records_skipped_write() -> None:
    result = run_cli("--mount-point", "/", "--read-only", "--timeout", "1")

    report = cli_report(result)
    assert result.returncode == health.EXIT_HEALTHY, result.stdout + result.stderr
    assert report["classification"] == "healthy"
    probes = {probe["name"]: probe for probe in report["probes"]}
    assert probes["readdir"]["verdict"] == "ok"
    assert probes["mkdir_rmdir"]["verdict"] == "skipped"
    assert probes["mkdir_rmdir"]["details"]["reason"] == "disabled by --read-only"


def test_default_mode_is_report_only_and_does_not_invent_an_action(tmp_path: Path) -> None:
    initial = assessment("unresponsive", tmp_path)

    report = health.build_report(initial)

    assert report["remediation"] == {
        "status": "not_requested",
        "message": "report-only mode",
    }
    assert report["status"] == "unresponsive"


def test_remediation_rechecks_and_takes_no_action_if_mount_recovers(tmp_path: Path) -> None:
    mount_point = tmp_path / "share"
    mount_point.mkdir()
    initial = assessment("unresponsive", mount_point)
    recovered = assessment("healthy", mount_point)
    runner = RecordingCommandRunner()

    result = health.remediate(
        initial,
        health.RemediationConfig(
            mount_point=mount_point,
            mount_command=("fake-mount", "{mount_point}"),
            unmount_command=("fake-unmount", "{mount_point}"),
        ),
        sequence_assessor(recovered),
        command_runner=runner,
    )

    assert result.status == "remediated"
    assert result.assessment.classification == "healthy"
    assert runner.calls == [], "state changed before action but a command still ran"


def test_remediation_handles_unmount_deleting_mountpoint_with_recreate_helper(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "volumes"
    parent.mkdir()
    mount_point = parent / "share"
    mount_point.mkdir()
    initial = assessment("unresponsive", mount_point)
    still_wedged = assessment("unresponsive", mount_point)
    recovered = assessment("healthy", mount_point)

    def mutate_for_command(command: tuple[str, ...]) -> None:
        if command[0] == "fake-unmount":
            mount_point.rmdir()
            parent.chmod(0o500)
        elif command[0] == "fake-recreate":
            parent.chmod(0o700)
            mount_point.mkdir()

    runner = RecordingCommandRunner(mutate_for_command)
    try:
        result = health.remediate(
            initial,
            health.RemediationConfig(
                mount_point=mount_point,
                mount_command=("fake-mount", "{mount_point}"),
                unmount_command=("fake-unmount", "{mount_point}"),
                recreate_command=("fake-recreate", "{mount_point}"),
            ),
            sequence_assessor(still_wedged, recovered),
            command_runner=runner,
        )
    finally:
        parent.chmod(0o700)

    assert result.status == "remediated"
    assert [call[0] for call in runner.calls] == [
        "fake-unmount",
        "fake-recreate",
        "fake-mount",
    ]
    actions = result.attempts[0]["actions"]
    ensure = next(action for action in actions if action["kind"] == "ensure_mountpoint")
    assert ensure["status"] == "recreated_by_command"


def test_removed_mountpoint_without_privilege_fails_loudly(tmp_path: Path) -> None:
    parent = tmp_path / "volumes"
    parent.mkdir()
    mount_point = parent / "share"
    mount_point.mkdir()
    initial = assessment("unresponsive", mount_point)
    still_wedged = assessment("unresponsive", mount_point)

    def delete_and_lock(command: tuple[str, ...]) -> None:
        if command[0] == "fake-unmount":
            mount_point.rmdir()
            parent.chmod(0o500)

    runner = RecordingCommandRunner(delete_and_lock)
    try:
        result = health.remediate(
            initial,
            health.RemediationConfig(
                mount_point=mount_point,
                mount_command=("fake-mount", "{mount_point}"),
                unmount_command=("fake-unmount", "{mount_point}"),
            ),
            sequence_assessor(still_wedged),
            command_runner=runner,
        )
    finally:
        parent.chmod(0o700)
        mount_point.mkdir(exist_ok=True)

    assert result.status == "remediation_failed"
    assert "privileged mkdir/chown repair" in result.message
    assert [call[0] for call in runner.calls] == ["fake-unmount"]
    actions = result.attempts[0]["actions"]
    ensure = next(action for action in actions if action["kind"] == "ensure_mountpoint")
    assert ensure["status"] == "failed"
    assert "privileged --recreate-command" in ensure["error"]


def test_fresh_mount_that_rewedges_stops_after_bounded_attempts(tmp_path: Path) -> None:
    mount_point = tmp_path / "share"
    mount_point.mkdir()
    wedged = assessment("unresponsive", mount_point)
    runner = RecordingCommandRunner()

    result = health.remediate(
        wedged,
        health.RemediationConfig(
            mount_point=mount_point,
            mount_command=("fake-mount", "{mount_point}"),
            unmount_command=("fake-unmount", "{mount_point}"),
            attempts=2,
        ),
        sequence_assessor(wedged, wedged, wedged, wedged),
        command_runner=runner,
    )

    assert result.status == "remediation_failed"
    assert "after 2 bounded remediation attempt(s)" in result.message
    assert "reboot may be required" in result.message
    assert len(result.attempts) == 2
    assert [call[0] for call in runner.calls] == [
        "fake-unmount",
        "fake-mount",
        "fake-unmount",
        "fake-mount",
    ]


def test_unknown_pre_action_probe_refuses_destructive_remediation(tmp_path: Path) -> None:
    mount_point = tmp_path / "share"
    mount_point.mkdir()
    initial = assessment("unresponsive", mount_point)
    unknown = health.Assessment(mount_point, "unknown", ())
    runner = RecordingCommandRunner()

    result = health.remediate(
        initial,
        health.RemediationConfig(
            mount_point=mount_point,
            mount_command=("fake-mount", "{mount_point}"),
            unmount_command=("fake-unmount", "{mount_point}"),
        ),
        sequence_assessor(unknown),
        command_runner=runner,
    )

    assert result.status == "remediation_failed"
    assert "refusing a destructive action" in result.message
    assert runner.calls == []


def test_missing_known_file_is_misconfigured_not_unresponsive(tmp_path: Path) -> None:
    """ENOENT inside the deadline is evidence the mount IS serving I/O."""

    result = health.assess_mount(
        tmp_path,
        known_file=Path("was-renamed.jsonl"),
        timeout=1.0,
        mount_entry_result=present_mount_result(),
    )

    assert result.classification == "misconfigured"
    readdir = next(probe for probe in result.probes if probe.name == "readdir")
    assert readdir.verdict == "ok", "the mount answered; that is the whole point"


def test_missing_known_file_does_not_arm_the_force_unmount(tmp_path: Path) -> None:
    """The regression that matters: a renamed file must not tear down a mount."""

    mount_point = tmp_path / "share"
    mount_point.mkdir()
    initial = health.assess_mount(
        mount_point,
        known_file=Path("was-renamed.jsonl"),
        timeout=1.0,
        mount_entry_result=present_mount_result(),
    )
    runner = RecordingCommandRunner()

    result = health.remediate(
        initial,
        health.RemediationConfig(
            mount_point=mount_point,
            mount_command=("fake-mount", "{mount_point}"),
            unmount_command=("fake-unmount", "{mount_point}"),
        ),
        sequence_assessor(initial),
        command_runner=runner,
    )

    assert result.status == "not_needed"
    assert runner.calls == [], "a missing file must never force-unmount a live mount"


def test_known_file_enoent_with_a_sick_mount_stays_unresponsive(tmp_path: Path) -> None:
    """The narrowing must not swallow a real wedge that also has a bad path."""

    result = health.assess_mount(
        tmp_path,
        known_file=Path("was-renamed.jsonl"),
        timeout=0.5,
        mount_entry_result=present_mount_result(),
        operations=health.ProbeOperations(
            readdir=blocking_readdir,
            mkdir_rmdir=health.DEFAULT_OPERATIONS.mkdir_rmdir,
            read_known_file=health.DEFAULT_OPERATIONS.read_known_file,
        ),
    )

    assert result.classification == "unresponsive"


def test_misconfigured_exit_code_is_nonzero_and_not_the_mount_problem_code() -> None:
    code = health.exit_code_for_report({"classification": "misconfigured"})

    assert code == health.EXIT_MISCONFIGURED
    assert code != health.EXIT_HEALTHY, "a bad --known-file is still a finding"
    assert code != health.EXIT_MOUNT_PROBLEM, "nothing about the mount needs recovery"


# ---------------------------------------------------------------------------
# A scoped pass must not read as a general one.
#
# Every probe runs under ONE interpreter binary. Where filesystem permissions are
# granted per binary, a healthy result here says nothing about any other program,
# so the report must NAME its limit.
# ---------------------------------------------------------------------------


def test_report_names_the_binary_it_tested():
    """A verdict about one binary must say which one."""
    coverage = health.probe_coverage()
    assert coverage["tested_binary"], "the report must name the binary the verdict covers"
    assert coverage["tested_binary"].startswith("/"), "an absolute, resolved path -- a symlink hides which binary TCC keyed on"
    assert coverage["scope"] == "one binary"


def test_report_declares_what_it_did_not_survey():
    """UNKNOWN out loud beats a clean bill that cannot be justified."""
    coverage = health.probe_coverage()
    text = coverage["not_surveyed"]
    assert "NOT SURVEYED" in text
    assert "PER-BINARY" in text, "the reason the scope is narrow must travel with the scope"
    assert "NOT evidence" in text, "must explicitly deny the fleet-wide reading"


def test_human_line_carries_the_coverage_limit():
    """The one line a human actually reads must not say 'healthy' unqualified."""
    report = {
        "status": "healthy",
        "classification": "healthy",
        "coverage": health.probe_coverage(),
        "remediation": {"status": "not_requested"},
    }

    # The real Assessment, not a stub. A hand-rolled fake lacked `probes` and the
    # test failed on the stub rather than on the behaviour -- a stub that cannot
    # represent the input is a blind spot, not a simplification.
    assessment = health.Assessment(Path("/mnt/share"), "healthy", ())
    line = health.render_human(report, assessment)
    assert "coverage=one-binary-only" in line, (
        "a bare status=healthy reads as 'every program here can use the mount', which is not what was tested"
    )
    assert "tested_binary=" in line


# ---------------------------------------------------------------------------
# The local positive control.
#
# A detector that has never been seen to observe a healthy write cannot report an
# unhealthy one. The control runs the SAME write probe through the SAME bounded
# subprocess machinery against local disk first; if that fails, the instrument
# is broken and the verdict is UNKNOWN, not "the mount is unresponsive".
# ---------------------------------------------------------------------------


def test_a_passing_control_is_recorded_before_the_mount_probes(tmp_path: Path) -> None:
    control = tmp_path / "control"
    control.mkdir()
    result = health.assess_mount(
        tmp_path, timeout=2.0, control_dir=control, mount_entry_result=present_mount_result()
    )
    assert result.classification == "healthy"
    assert [p.name for p in result.probes][:2] == ["local_control", "mount_entry"]
    assert result.probes[0].verdict == "ok"
    assert list(control.iterdir()) == [], "the control must clean up after itself"


def test_a_failing_control_makes_the_verdict_unknown_not_unresponsive(tmp_path: Path) -> None:
    """MUST-FIRE: with a broken instrument, a mount failure would be indistinguishable."""
    result = health.assess_mount(
        tmp_path,
        timeout=2.0,
        control_dir=tmp_path / "does-not-exist",
        mount_entry_result=present_mount_result(),
    )
    assert result.classification == "unknown"
    assert result.probes[0].name == "local_control"
    assert result.probes[0].verdict == "error"
    assert all(p.verdict == "skipped" for p in result.probes[1:]), (
        "no mount probe may run, and no verdict may be drawn, once the control has failed"
    )
    assert health.exit_code_for_report(health.build_report(result)) == health.EXIT_UNKNOWN


def test_a_control_that_cannot_finish_is_unknown(tmp_path: Path) -> None:
    operations = health.ProbeOperations(
        readdir=health.DEFAULT_OPERATIONS.readdir,
        mkdir_rmdir=blocking_write,
        read_known_file=health.DEFAULT_OPERATIONS.read_known_file,
    )
    started = time.monotonic()
    result = health.assess_mount(tmp_path, timeout=0.2, control_dir=tmp_path,
                                 operations=operations, mount_entry_result=present_mount_result())
    assert time.monotonic() - started < 2.0
    assert result.classification == "unknown"
    assert result.probes[0].verdict == "timeout"


def test_cli_runs_the_control_by_default_and_can_skip_it(tmp_path: Path) -> None:
    with_control = cli_report(run_cli("--mount-point", str(tmp_path), "--timeout", "2"))
    assert with_control["probes"][0]["name"] == "local_control"
    without = cli_report(run_cli("--mount-point", str(tmp_path), "--timeout", "2", "--no-control"))
    assert without["probes"][0]["name"] == "mount_entry"


def test_cli_requires_a_mount_point() -> None:
    result = run_cli()
    assert result.returncode == health.EXIT_MISCONFIGURED
    assert "--mount-point" in result.stdout


def test_exit_codes_follow_the_shared_convention() -> None:
    assert health.exit_code_for_report({"classification": "healthy"}) == 0
    assert health.exit_code_for_report({"classification": "unresponsive"}) == 1
    assert health.exit_code_for_report({"classification": "absent"}) == 1
    assert health.exit_code_for_report({"status": "remediation_failed"}) == 1
    assert health.exit_code_for_report({"classification": "misconfigured"}) == 2
    assert health.exit_code_for_report({"classification": "unknown"}) == 3


# ---------------------------------------------------------------------------
# Reads can be answered from a cache; the write is what reaches the server.
# ---------------------------------------------------------------------------


def test_a_listing_that_answers_while_the_write_hangs_is_unresponsive(tmp_path: Path) -> None:
    """MUST-FIRE: the exact case `ls`-based monitoring calls healthy."""
    operations = health.ProbeOperations(
        readdir=health.DEFAULT_OPERATIONS.readdir,
        mkdir_rmdir=blocking_write,
        read_known_file=health.DEFAULT_OPERATIONS.read_known_file,
    )
    started = time.monotonic()
    result = health.assess_mount(tmp_path, timeout=0.3, operations=operations,
                                 mount_entry_result=present_mount_result())
    assert time.monotonic() - started < 3.0, "the blocked write escaped its hard timeout"
    verdicts = {p.name: p.verdict for p in result.probes}
    assert verdicts["readdir"] == "ok", "the listing answered: that is the point of the test"
    assert verdicts["mkdir_rmdir"] == "timeout"
    assert result.classification == "unresponsive"


def test_a_listing_that_answers_while_the_write_is_refused_is_unresponsive(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "existing.txt").write_text("x")
    locked.chmod(0o500)
    try:
        result = health.assess_mount(locked, timeout=2.0, mount_entry_result=present_mount_result())
    finally:
        locked.chmod(0o700)
    verdicts = {p.name: p.verdict for p in result.probes}
    if os.geteuid() == 0:  # root ignores directory permissions; nothing to assert
        return
    assert verdicts["readdir"] == "ok"
    assert verdicts["mkdir_rmdir"] == "error"
    assert result.classification == "unresponsive"


def test_every_human_line_carries_the_coverage_limit_including_misconfiguration() -> None:
    result = run_cli("--remediate", "--mount-point", "/")  # misconfigured: no --mount-command
    assert result.returncode == health.EXIT_MISCONFIGURED
    human = result.stdout.splitlines()[1]
    assert human.startswith("MOUNT_PROBE status=misconfigured")
    assert "coverage=one-binary-only" in human and "tested_binary=" in human


def test_json_mode_prints_only_the_report(tmp_path: Path) -> None:
    result = run_cli("--mount-point", str(tmp_path), "--timeout", "2", "--json")
    lines = result.stdout.splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["classification"] == "absent"
