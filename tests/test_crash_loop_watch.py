"""Tests for the launchd crash-loop watch.

launchd and ssh are faked at their boundaries (``capture_launchctl_artifacts`` and ``_run_ssh``);
the parser runs against full ``launchctl print`` artifacts, with paths and names replaced by
neutral ones and launchd's structure left intact.
"""

from __future__ import annotations

import json
import stat
from collections import Counter
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from honest_watchdogs import crash_loop_watch as watch

PREFIX = "com.example."

# A long-running KeepAlive worker, as `launchctl print gui/501/<label>` shows it.
HEALTHY_WORKER_PRINT = """gui/501/com.example.queue-worker = {
\tactive count = 1
\tpath = /Library/LaunchAgents/com.example.queue-worker.plist
\ttype = LaunchAgent
\tstate = running

\tprogram = /opt/example/bin/queue-worker
\targuments = {
\t\t/opt/example/bin/queue-worker
\t\t--concurrency
\t\t4
\t}

\tworking directory = /opt/example

\tstdout path = /tmp/queue-worker.out.log
\tstderr path = /tmp/queue-worker.err.log
\tinherited environment = {
\t\tSSH_AUTH_SOCK => /var/run/com.apple.launchd.XXXXXXXXXX/Listeners
\t}

\tdefault environment = {
\t\tPATH => /usr/bin:/bin:/usr/sbin:/sbin
\t}

\tenvironment = {
\t\tOSLogRateLimit => 64
\t\tPATH => /usr/bin:/bin
\t\tXPC_SERVICE_NAME => com.example.queue-worker
\t}

\tdomain = gui/501 [100016]
\tasid = 100016
\tminimum runtime = 30
\texit timeout = 5
\truns = 371
\tpid = 3438
\timmediate reason = semaphore
\tforks = 6
\texecs = 2
\tinitialized = 1
\ttrampolined = 1
\tstarted suspended = 0
\tproxy started suspended = 0
\tchecked allocations = 0 (queried = 1)
\tchecked allocations reason = no host
\tchecked allocations flags = 0x0
\tlast terminating signal = Terminated: 15

\tsemaphores = {
\t\tsuccessful exit => 0
\t\tafter crash => 1
\t}

\tresource coalition = {
\t\tID = 280936
\t\ttype = resource
\t\tstate = active
\t\tactive count = 1
\t\tname = com.example.queue-worker
\t}

\tjetsam coalition = {
\t\tID = 280937
\t\ttype = jetsam
\t\tstate = active
\t\tactive count = 1
\t\tname = com.example.queue-worker
\t}

\tspawn type = daemon (3)
\tjetsam priority = 40
\tjetsam memory limit (active) = (unlimited)
\tjetsam memory limit (inactive) = (unlimited)
\tjetsamproperties category = daemon
\tjetsam thread limit = 32
\tcpumon = default

\tproperties = runatload | inferred program
}
"""

# An hourly StartInterval job between runs.
PERIODIC_PRINT = """gui/501/com.example.hourly-sweep = {
\tactive count = 0
\tpath = /Library/LaunchAgents/com.example.hourly-sweep.plist
\ttype = LaunchAgent
\tstate = not running

\tprogram = /bin/zsh
\targuments = {
\t\t/bin/zsh
\t\t-lc
\t\tset -eu; exec /opt/example/bin/python /opt/example/sweep.py
\t}

\tworking directory = /opt/example

\tstdout path = /tmp/hourly-sweep.out.log
\tstderr path = /tmp/hourly-sweep.err.log
\tinherited environment = {
\t\tSSH_AUTH_SOCK => /var/run/com.apple.launchd.XXXXXXXXXX/Listeners
\t}

\tdefault environment = {
\t\tPATH => /usr/bin:/bin:/usr/sbin:/sbin
\t}

\tenvironment = {
\t\tOSLogRateLimit => 64
\t\tXPC_SERVICE_NAME => com.example.hourly-sweep
\t}

\tdomain = gui/501 [100016]
\tasid = 100016
\tminimum runtime = 10
\texit timeout = 5
\truns = 7
\tlast exit code = 0

\tresource coalition = {
\t\tID = 440502
\t\ttype = resource
\t\tstate = active
\t\tactive count = 1
\t\tname = com.example.hourly-sweep
\t}

\tjetsam coalition = {
\t\tID = 440503
\t\ttype = jetsam
\t\tstate = active
\t\tactive count = 1
\t\tname = com.example.hourly-sweep
\t}

\tspawn type = daemon (3)
\tjetsam priority = 40
\tjetsam memory limit (active) = (unlimited)
\tjetsam memory limit (inactive) = (unlimited)
\tjetsamproperties category = daemon
\tjetsam thread limit = 32
\tcpumon = default
\trun interval = 3600 seconds

\tproperties = runatload | inferred program
}
"""

# An on-demand agent that has never run: runs=0, "(never exited)", and an event-trigger block.
NEVER_RUN_PRINT = """gui/501/com.example.on-demand = {
\tactive count = 0
\tpath = /Library/LaunchAgents/com.example.on-demand.plist
\ttype = LaunchAgent
\tstate = not running

\tprogram = /opt/example/bin/on-demand
\tinherited environment = {
\t\tSSH_AUTH_SOCK => /var/run/com.apple.launchd.XXXXXXXXXX/Listeners
\t}

\tdefault environment = {
\t\tPATH => /usr/bin:/bin:/usr/sbin:/sbin
\t}

\tenvironment = {
\t\tOSLogRateLimit => 64
\t\tXPC_SERVICE_NAME => com.example.on-demand
\t}

\tdomain = gui/501 [100016]
\tasid = 100016
\tminimum runtime = 10
\tbase minimum runtime = 10
\texit timeout = 5
\truns = 0
\tlast exit code = (never exited)

\tevent triggers = {
\t\tcom.apple.launchd.PathState => {
\t\t\tkeepalive = 0
\t\t\tservice = com.example.on-demand
\t\t\tstream = com.apple.fsevents.matching
\t\t\tmonitor = com.apple.UserEventAgent-Aqua
\t\t\tdescriptor = {
\t\t\t\t"PathState" => {
\t\t\t\t\t"~/Library/Example/Trigger" => true
\t\t\t\t}
\t\t\t}
\t\t}
\t}

\tspawn type = daemon (3)
\tjetsam priority = 40
\tjetsam memory limit (active) = (unlimited)
\tjetsam memory limit (inactive) = (unlimited)
\tjetsamproperties category = daemon
\tjetsam thread limit = 32
\tcpumon = default

\tproperties = exponential throttling
}
"""

FIXTURE_CRASH_LABEL = "com.example.fixture-crash-loop"


def _snapshot(
    *,
    label: str = FIXTURE_CRASH_LABEL,
    runs: int,
    exit_code: int | None,
    state: str = "spawn scheduled",
    signal: str | None = None,
    periodic: bool = False,
) -> watch.LaunchdJobSnapshot:
    return watch.LaunchdJobSnapshot(
        label=label,
        state=state,
        runs=runs,
        last_exit_code=exit_code,
        last_exit_raw="" if exit_code is None else str(exit_code),
        pid=None,
        last_terminating_signal=signal,
        run_interval_seconds=60 if periodic else None,
        has_event_triggers=False,
    )


def _evaluate(
    snapshot: watch.LaunchdJobSnapshot,
    state: dict[str, object],
    *,
    now: float,
    config: watch.WatchConfig | None = None,
) -> watch.Evaluation:
    return watch.evaluate_observations(
        (snapshot,),
        state,
        config=config or watch.WatchConfig(no_alert=True),
        now=now,
        uid=501,
    )


def test_parser_reads_real_healthy_worker_launchctl_print() -> None:
    job = watch.parse_launchctl_print(
        HEALTHY_WORKER_PRINT,
        expected_label="com.example.queue-worker",
    )

    assert job.state == "running"
    assert job.runs == 371
    assert job.pid == 3438
    assert job.last_exit_code is None
    assert job.last_terminating_signal == "Terminated: 15"
    assert job.periodic is False


def test_parser_reads_real_periodic_launchctl_print() -> None:
    job = watch.parse_launchctl_print(PERIODIC_PRINT)

    assert job.label == "com.example.hourly-sweep"
    assert job.state == "not running"
    assert job.runs == 7
    assert job.last_exit_code == 0
    assert job.run_interval_seconds == 3600
    assert job.periodic is True


def test_parser_reads_real_never_run_launchctl_print() -> None:
    job = watch.parse_launchctl_print(NEVER_RUN_PRINT)

    assert job.runs == 0
    assert job.last_exit_raw == "(never exited)"
    assert job.last_exit_code is None
    assert job.has_event_triggers is True


def test_positive_control_repeated_nonzero_exits_reports_fixture_job_as_crash_looping() -> None:
    """MUST DETECT: repeated positive exits in the bounded window name the fixture job."""

    config = watch.WatchConfig(window_seconds=600, threshold=3, no_alert=True)
    state = watch.empty_state()
    evaluations: list[watch.Evaluation] = []
    for now, runs in ((1_000.0, 100), (1_060.0, 102), (1_120.0, 104), (1_180.0, 106)):
        evaluation = _evaluate(
            _snapshot(runs=runs, exit_code=1),
            state,
            now=now,
            config=config,
        )
        evaluations.append(evaluation)
        state = evaluation.next_state

    final = evaluations[-1]
    classifications = {job.label: job.verdict for job in final.jobs}
    assert classifications == {
        FIXTURE_CRASH_LABEL: "crash_looping"
    }, "fixture crash-loop job must be classified crash_looping from repeated exit-1 evidence"
    report = watch.report_dict(final, config=config)
    assert report["summary"] == {
        "total": 1,
        "by_verdict": {"crash_looping": 1},
        "crash_looping": [FIXTURE_CRASH_LABEL],
        "unknown": [],
        "coverage_complete": True,
        "error_count": 0,
    }
    job = report["jobs"][0]
    evidence = job["respawn_restart_evidence"]
    assert evidence["observed_nonzero_exit_count"] == 3
    assert evidence["observed_runs_advanced"] == 6
    assert evidence["latest_observed_nonzero_exit_code"] == 1
    assert evidence["window_seconds"] == 600
    assert final.pending_alerts == (
        watch.PendingCrashLoopAlert(
            label=FIXTURE_CRASH_LABEL,
            exit_code=1,
            count=3,
            window_seconds=600,
            runs_advanced=6,
        ),
    )


def test_single_deliberate_kickstart_signal_does_not_fire() -> None:
    state = _evaluate(
        _snapshot(runs=10, exit_code=None, state="running"),
        watch.empty_state(),
        now=1_000.0,
    ).next_state
    result = _evaluate(
        _snapshot(
            runs=11,
            exit_code=None,
            state="running",
            signal="Terminated: 15",
        ),
        state,
        now=1_060.0,
    )

    assert {job.label: job.verdict for job in result.jobs} == {
        FIXTURE_CRASH_LABEL: "healthy"
    }
    assert result.jobs[0].respawn_restart_evidence["last_terminating_signal"] == (
        "Terminated: 15"
    )
    assert result.pending_alerts == ()


def test_periodic_job_exiting_zero_does_not_fire() -> None:
    periodic = watch.parse_launchctl_print(PERIODIC_PRINT)
    prior = _evaluate(replace(periodic, runs=6), watch.empty_state(), now=1_000.0).next_state
    result = _evaluate(periodic, prior, now=1_060.0)

    assert {job.label: job.verdict for job in result.jobs} == {
        periodic.label: "healthy"
    }
    assert result.pending_alerts == ()


def test_periodic_nonzero_on_findings_contract_does_not_fire() -> None:
    periodic = watch.parse_launchctl_print(PERIODIC_PRINT)
    config = watch.WatchConfig(
        no_alert=True,
        nonzero_findings_labels=frozenset({periodic.label}),
    )
    prior = _evaluate(
        replace(periodic, runs=6),
        watch.empty_state(),
        now=1_000.0,
        config=config,
    ).next_state
    result = _evaluate(
        replace(periodic, runs=7, last_exit_code=1, last_exit_raw="1"),
        prior,
        now=1_060.0,
        config=config,
    )

    assert {job.label: (job.verdict, job.contract) for job in result.jobs} == {
        periodic.label: ("expected_nonzero", "nonzero_on_findings")
    }
    assert result.jobs[0].respawn_restart_evidence["contract_applied"] is True
    assert result.pending_alerts == ()


def test_findings_exemption_is_not_applied_to_unscheduled_service() -> None:
    config = watch.WatchConfig(
        threshold=2,
        no_alert=True,
        nonzero_findings_labels=frozenset({FIXTURE_CRASH_LABEL}),
    )
    state = _evaluate(
        _snapshot(runs=10, exit_code=1),
        watch.empty_state(),
        now=1_000.0,
        config=config,
    ).next_state
    state = _evaluate(
        _snapshot(runs=11, exit_code=1),
        state,
        now=1_060.0,
        config=config,
    ).next_state
    result = _evaluate(
        _snapshot(runs=12, exit_code=1),
        state,
        now=1_120.0,
        config=config,
    )

    assert {job.label: (job.verdict, job.contract) for job in result.jobs} == {
        FIXTURE_CRASH_LABEL: ("crash_looping", "standard")
    }


def test_never_run_job_does_not_fire() -> None:
    never_run = watch.parse_launchctl_print(NEVER_RUN_PRINT)
    result = _evaluate(never_run, watch.empty_state(), now=1_000.0)

    assert {job.label: job.verdict for job in result.jobs} == {
        never_run.label: "never_run"
    }
    assert result.pending_alerts == ()


def test_run_counter_reset_clears_failure_history_as_reboot_reload_evidence() -> None:
    config = watch.WatchConfig(threshold=2, no_alert=True)
    state = watch.empty_state()
    for now, runs in ((1_000.0, 100), (1_060.0, 101), (1_120.0, 102)):
        evaluation = _evaluate(
            _snapshot(runs=runs, exit_code=1),
            state,
            now=now,
            config=config,
        )
        state = evaluation.next_state
    assert evaluation.jobs[0].verdict == "crash_looping"

    reset = _evaluate(
        _snapshot(runs=1, exit_code=1),
        state,
        now=1_180.0,
        config=config,
    )

    assert reset.jobs[0].verdict == "observing"
    assert reset.jobs[0].respawn_restart_evidence["counter_reset"] is True
    assert reset.jobs[0].respawn_restart_evidence["observed_nonzero_exit_count"] == 0
    assert reset.pending_alerts == ()


def test_failure_evidence_expires_outside_bounded_window() -> None:
    config = watch.WatchConfig(window_seconds=120, threshold=2, no_alert=True)
    state = watch.empty_state()
    for now, runs in ((1_000.0, 10), (1_030.0, 11), (1_060.0, 12)):
        evaluation = _evaluate(
            _snapshot(runs=runs, exit_code=1),
            state,
            now=now,
            config=config,
        )
        state = evaluation.next_state
    assert evaluation.jobs[0].verdict == "crash_looping"

    expired = _evaluate(
        _snapshot(runs=12, exit_code=1),
        state,
        now=1_181.0,
        config=config,
    )

    assert expired.jobs[0].verdict == "healthy"
    assert expired.pending_alerts == ()


def test_unreadable_discovered_job_is_unknown_in_json_artifacts() -> None:
    label = "com.example.unreadable-fixture"
    labels = watch.parse_launchctl_list(f"PID\tStatus\tLabel\n-\t0\t{label}\n", PREFIX)
    observations = watch.observations_from_artifacts(
        labels,
        {
            label: watch.CommandArtifact(
                returncode=113,
                stderr="Could not find service in domain for user gui: 501",
            )
        },
    )
    evaluation = watch.evaluate_observations(
        observations,
        watch.empty_state(),
        config=watch.WatchConfig(no_alert=True),
        now=1_000.0,
        uid=501,
    )
    report = watch.report_dict(evaluation, config=watch.WatchConfig(no_alert=True))

    assert {job["label"]: job["verdict"] for job in report["jobs"]} == {
        label: "unknown"
    }, "an unreadable discovered job must be classified unknown, never healthy"
    assert report["summary"]["crash_looping"] == []
    assert report["summary"]["unknown"] == [label]
    assert report["summary"]["coverage_complete"] is False


def test_missing_or_empty_discovery_source_fails_loudly() -> None:
    with pytest.raises(
        watch.LaunchdDiscoveryError,
        match=r"no com\.example\.\* jobs; coverage is unknown",
    ):
        watch.parse_launchctl_list("PID\tStatus\tLabel\n", PREFIX)


def test_discovery_keeps_only_prefixed_jobs() -> None:
    stdout = """PID\tStatus\tLabel
1\t0\tcom.example.bridge
-\t0\tcom.apple.Finder
2\t0\tcom.example.queue-worker
"""

    assert watch.parse_launchctl_list(stdout, PREFIX) == (
        "com.example.bridge",
        "com.example.queue-worker",
    )


def test_malformed_print_artifact_becomes_unknown_instead_of_healthy() -> None:
    label = "com.example.malformed"
    observations = watch.observations_from_artifacts(
        (label,),
        {
            label: watch.CommandArtifact(
                returncode=0,
                stdout=f"gui/502/{label} = {{\n\tstate = running\n}}\n",
            )
        },
    )

    assert observations == (
        watch.UnknownObservation(
            label=label,
            reason=f"{label}: launchctl print has invalid runs=None",
        ),
    )


def test_corrupt_state_fails_loudly_and_is_not_replaced(tmp_path: Path) -> None:
    state_path = tmp_path / "health.json"
    state_path.write_text("{not-json\n", encoding="utf-8")

    with pytest.raises(watch.HealthStateError, match="is invalid JSON"):
        watch.load_state(state_path)

    assert state_path.read_text(encoding="utf-8") == "{not-json\n"


def test_state_round_trip_is_owner_only(tmp_path: Path) -> None:
    state_path = tmp_path / "state" / "health.json"
    state = _evaluate(
        _snapshot(runs=10, exit_code=1),
        watch.empty_state(),
        now=1_000.0,
    ).next_state

    watch.save_state(state_path, state)

    assert watch.load_state(state_path)["jobs"] == state["jobs"]
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600


def test_alert_success_marks_incident_once_and_same_sample_does_not_repage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(watch.socket, "gethostname", lambda: "builder.example.test")
    config = watch.WatchConfig(threshold=2)
    state = watch.empty_state()
    for now, runs in ((1_000.0, 10), (1_060.0, 11), (1_120.0, 12)):
        evaluation = _evaluate(
            _snapshot(runs=runs, exit_code=1),
            state,
            now=now,
            config=config,
        )
        state = evaluation.next_state
    calls: list[dict[str, object]] = []

    def successful_alert(**kwargs: object) -> SimpleNamespace:
        calls.append(kwargs)
        return SimpleNamespace(success=True)

    assert watch.deliver_pending_alerts(
        evaluation,
        config=config,
        alert_sender=successful_alert,
    ) == ()
    state = evaluation.next_state
    unchanged = _evaluate(
        _snapshot(runs=12, exit_code=1),
        state,
        now=1_130.0,
        config=config,
    )

    assert len(calls) == 1
    assert calls[0]["label"] == FIXTURE_CRASH_LABEL
    assert calls[0]["exit_code"] == 1
    assert calls[0]["observed_nonzero_exit_count"] == 2
    assert calls[0]["window_seconds"] == 600
    assert calls[0]["host"] == "builder", (
        "every watcher delivery must identify the current host by its short name"
    )
    assert unchanged.pending_alerts == ()


def test_failed_alert_remains_pending_for_retry() -> None:
    config = watch.WatchConfig(threshold=2)
    state = watch.empty_state()
    for now, runs in ((1_000.0, 10), (1_060.0, 11), (1_120.0, 12)):
        evaluation = _evaluate(
            _snapshot(runs=runs, exit_code=1),
            state,
            now=now,
            config=config,
        )
        state = evaluation.next_state

    errors = watch.deliver_pending_alerts(
        evaluation,
        config=config,
        alert_sender=lambda **kwargs: SimpleNamespace(success=False),
    )
    retry = _evaluate(
        _snapshot(runs=12, exit_code=1),
        evaluation.next_state,
        now=1_130.0,
        config=config,
    )

    assert errors == (
        {
            "scope": "alert",
            "label": FIXTURE_CRASH_LABEL,
            # This sender exposes no deliveries at all, so the record must SAY
            # the reason is absent rather than read as a clean generic failure.
            "error": (
                "alert delivery returned unsuccessful: "
                "(sender reported no per-sink reason)"
            ),
        },
    )
    assert retry.pending_alerts[0].label == FIXTURE_CRASH_LABEL


def test_human_table_and_json_name_actionable_crash_evidence() -> None:
    config = watch.WatchConfig(threshold=2, no_alert=True)
    state = watch.empty_state()
    for now, runs in ((1_000.0, 10), (1_060.0, 11), (1_120.0, 12)):
        evaluation = _evaluate(
            _snapshot(runs=runs, exit_code=7),
            state,
            now=now,
            config=config,
        )
        state = evaluation.next_state
    report = watch.report_dict(evaluation, config=config)
    encoded = json.dumps(report)
    table = watch.format_human_table(report)

    assert FIXTURE_CRASH_LABEL in encoded
    assert '"crash_looping": ["com.example.fixture-crash-loop"]' in encoded
    assert FIXTURE_CRASH_LABEL in table
    assert "spawn scheduled" in table
    assert "7" in table
    assert "2/600s" in table
    assert "crash_looping" in table


def test_healthy_report_is_quiet_unless_show_all_is_requested() -> None:
    config = watch.WatchConfig(no_alert=True)
    healthy = _evaluate(
        _snapshot(runs=10, exit_code=0, state="running"),
        watch.empty_state(),
        now=1_000.0,
        config=config,
    )
    report = watch.report_dict(healthy, config=config)

    assert watch.should_emit_report(report, show_all=False) is False
    assert watch.should_emit_report(report, show_all=True) is True


def test_unknown_and_crash_reports_break_healthy_silence() -> None:
    config = watch.WatchConfig(no_alert=True)
    unknown = watch.evaluate_observations(
        (watch.UnknownObservation(label="com.example.unknown", reason="unreadable"),),
        watch.empty_state(),
        config=config,
        now=1_000.0,
        uid=501,
    )
    unknown_report = watch.report_dict(unknown, config=config)

    assert watch.should_emit_report(unknown_report, show_all=False) is True


def test_default_scheduled_exit_contract_does_not_make_findings_nonzero() -> None:
    config = watch.WatchConfig(no_alert=True)
    evaluation = watch.Evaluation(
        generated_at=1_000.0,
        uid=501,
        jobs=(),
        next_state=watch.empty_state(),
        pending_alerts=(),
    )
    report = watch.report_dict(evaluation, config=config)

    # Detection is conveyed in JSON and pages. The scheduled command reserves
    # non-zero for observation/delivery failures unless explicitly opted into
    # --fail-on-crash-loop, avoiding a "non-zero is normal" launchd contract.
    assert report["errors"] == []
    assert config.fail_on_crash_loop is False


class TestAlertFailureCarriesItsCause:
    """The alert error record is the ONLY artifact a delivery failure produces.

    Nothing raises and nothing else logs it, so a bare "alert delivery returned
    unsuccessful" names the symptom and throws the cause away. A typical cause is a
    TLS certificate-store problem in one interpreter while command-line tools work
    fine: invisible unless the record carries the per-sink reason, because the only
    channel that could report it is the channel that is broken.
    """

    @staticmethod
    def _evaluation(tmp_path):
        pending = watch.PendingCrashLoopAlert(
            label="com.example.test.job",
            exit_code=2,
            count=3,
            window_seconds=600,
            runs_advanced=3,
        )
        return SimpleNamespace(
            pending_alerts=(pending,), next_state={}, generated_at=1788800000.0
        )

    @staticmethod
    def _config(tmp_path):
        return watch.WatchConfig(
            state_path=tmp_path / "state.json",
            window_seconds=600,
            threshold=3,
            launchctl_timeout_seconds=10,
            nonzero_findings_labels=frozenset(),
            no_alert=False,
            show_all=False,
            fail_on_crash_loop=False,
        )

    def _deliver(self, tmp_path, delivery):
        result = SimpleNamespace(success=False, deliveries=(delivery,))
        return watch.deliver_pending_alerts(
            self._evaluation(tmp_path),
            config=self._config(tmp_path),
            alert_sender=lambda **_: result,
        )

    def test_failure_reason_reaches_the_error_record(self, tmp_path):
        errors = self._deliver(
            tmp_path,
            SimpleNamespace(
                sink="webhook",
                success=False,
                failure_reason="request failed: SSLCertVerificationError",
                http_status=None,
            ),
        )
        assert len(errors) == 1
        message = str(errors[0]["error"])
        assert "SSLCertVerificationError" in message, (
            f"the cause was discarded; the error said only: {message!r}"
        )

    def test_absent_reason_is_stated_rather_than_implied(self, tmp_path):
        """MUST-STILL-FIRE: a sender giving no reason must SAY so, not read clean."""
        errors = self._deliver(
            tmp_path,
            SimpleNamespace(
                sink="webhook", success=False, failure_reason=None, http_status=None
            ),
        )
        assert "no per-sink reason" in str(errors[0]["error"])


class TestAnIncidentThatNeverEndsMustNotGoQuiet:
    """The shape: a job with StartInterval AND KeepAlive{SuccessfulExit:false} is
    respawned on launchd's 10s throttle instead of its interval. An upstream API
    answers 429, the job exits 1, and the loop's own volume keeps the 429 alive. The
    watcher classifies it `crash_looping` correctly on every tick and the first page
    is delivered.

    Then, without reminders, nothing, for as long as the loop lasts. `incident_alerted`
    latches on that delivery and only clears on exit 0, a run-counter reset, or the
    evidence window emptying -- none of which a permanent loop ever produces. The
    detector is right, the channel works, the page lands, and the incident still goes
    dark.

    Alert-once is correct for a condition that ENDS. For one that does not, the first
    page is also the last.

    These tests drive the REAL 60-second tick rather than jumping the clock, because
    jumping it empties the bounded evidence window and stops reproducing the incident.
    """

    TICK = 60.0
    START = 1_000.0

    def _run(
        self,
        config: watch.WatchConfig,
        *,
        ticks: int,
        exit_code: int = 1,
        state: dict[str, object] | None = None,
        deliver: bool = True,
        alert_succeeds: bool = True,
        start_runs: int = 10,
        start_at: float | None = None,
    ) -> tuple[dict[str, object], list[float], float, int]:
        """Tick a still-failing job forward, delivering pages as the watcher would."""
        state = watch.empty_state() if state is None else state
        paged_at: list[float] = []
        now = self.START if start_at is None else start_at
        runs = start_runs
        for _ in range(ticks):
            evaluation = _evaluate(
                _snapshot(runs=runs, exit_code=exit_code), state, now=now, config=config
            )
            if deliver and evaluation.pending_alerts:
                paged_at.append(now)
                watch.deliver_pending_alerts(
                    evaluation,
                    config=config,
                    alert_sender=lambda **_: SimpleNamespace(
                        success=alert_succeeds, deliveries=()
                    ),
                )
            state = evaluation.next_state
            now += self.TICK
            runs += 1
        return state, paged_at, now, runs

    def test_a_week_of_continuous_crash_looping_pages_more_than_once(self) -> None:
        config = watch.WatchConfig(threshold=3, reminder_seconds=21_600)
        # 24h of 60s ticks: the real cadence, in the real window.
        _, paged_at, _, _ = self._run(config, ticks=24 * 60)

        assert len(paged_at) >= 4, (
            "a day of unbroken crash-looping paged "
            f"{len(paged_at)} times; alert-once is what hid seven days of it"
        )
        gaps = [b - a for a, b in zip(paged_at, paged_at[1:])]
        assert all(gap >= 21_600 for gap in gaps), f"re-paged early: {gaps}"
        assert all(gap <= 21_600 + self.TICK for gap in gaps), f"re-paged late: {gaps}"

    def test_alert_once_is_still_the_rule_inside_the_interval(self) -> None:
        config = watch.WatchConfig(threshold=3, reminder_seconds=21_600)
        _, paged_at, _, _ = self._run(config, ticks=60)  # one hour

        assert len(paged_at) == 1, f"paged {len(paged_at)} times in an hour"

    def test_a_failed_repage_stays_due_instead_of_consuming_the_interval(self) -> None:
        config = watch.WatchConfig(threshold=3, reminder_seconds=21_600)
        state, paged, now, runs = self._run(
            config, ticks=10, alert_succeeds=False
        )
        assert len(paged) > 1, (
            "a page that never succeeded stopped being retried; failed delivery must "
            "leave the incident un-latched"
        )

    def test_recovery_clears_the_latch_and_its_timestamp(self) -> None:
        config = watch.WatchConfig(threshold=3, reminder_seconds=21_600)
        state, _, now, runs = self._run(config, ticks=10)

        recovered = _evaluate(
            _snapshot(runs=runs, exit_code=0), state, now=now, config=config
        )
        entry = recovered.next_state["jobs"][FIXTURE_CRASH_LABEL]
        assert entry["incident_alerted"] is False
        assert entry["incident_alerted_at"] is None
        assert recovered.jobs[0].verdict == "healthy"

    def test_reminders_can_be_switched_off(self) -> None:
        """0 restores the exact behaviour that produced the incident."""
        config = watch.WatchConfig(threshold=3, reminder_seconds=0)
        _, paged_at, _, _ = self._run(config, ticks=24 * 60)

        assert len(paged_at) == 1

    def test_state_written_before_reminders_existed_is_treated_as_due(self) -> None:
        """The upgrade must not inherit the silence of the state it reads."""
        config = watch.WatchConfig(threshold=3, reminder_seconds=21_600)
        state, paged_at, now, runs = self._run(config, ticks=10)
        assert len(paged_at) == 1

        # What a pre-reminder build wrote: latched, with no timestamp beside it.
        del state["jobs"][FIXTURE_CRASH_LABEL]["incident_alerted_at"]

        resumed = _evaluate(
            _snapshot(runs=runs, exit_code=1), state, now=now, config=config
        )
        assert resumed.pending_alerts, (
            "an incident latched by an older build stayed silent forever after upgrade"
        )

    def test_reminder_seconds_reaches_the_report_and_rejects_nonsense(self) -> None:
        config = watch.WatchConfig(reminder_seconds=900)
        evaluation = _evaluate(_snapshot(runs=1, exit_code=0), watch.empty_state(), now=1.0)
        report = watch.report_dict(evaluation, config=config)

        assert report["policy"]["reminder_seconds"] == 900
        with pytest.raises(ValueError):
            watch.WatchConfig(reminder_seconds=-1)


# --- Remote --host checks ------------------------------------------------------
#
# A per-host watcher cannot watch a machine that holds no alert credentials of
# its own. The remote form reads that machine's launchctl over ssh FROM the
# watcher. The ssh boundary is faked here so the suite needs no live host.


REMOTE_CRASH_LABEL = "com.example.fixture-crash-loop"
LOCAL_FIXTURE_LABEL = "com.example.browser"
REMOTE_UID = 501


def _print_artifact(
    uid: int,
    label: str,
    *,
    runs: int,
    exit_code: int | None,
) -> watch.CommandArtifact:
    exit_raw = "(never exited)" if exit_code is None else str(exit_code)
    stdout = (
        f"gui/{uid}/{label} = {{\n"
        "\tactive count = 0\n"
        "\ttype = LaunchAgent\n"
        "\tstate = not running\n"
        f"\truns = {runs}\n"
        f"\tlast exit code = {exit_raw}\n"
        "\trun interval = 60 seconds\n"
        "\tproperties = \n}\n"
    )
    return watch.CommandArtifact(returncode=0, stdout=stdout)


class _RemoteSshStub:
    """Canned ssh boundary for exactly one remote host's launchd inventory.

    ``jobs`` maps a label to ``callable(call_index) -> (runs, exit_code)`` so
    a test can advance the run counter between watcher ticks. ``fail`` models
    an unreachable host: every call returns an error artifact.
    """

    def __init__(
        self,
        host: str = "remote-mac",
        *,
        uid: int = REMOTE_UID,
        jobs: dict | None = None,
        fail: str | None = None,
    ) -> None:
        self.host = host
        self.uid = uid
        self.jobs = jobs or {}
        self.fail = fail
        self._calls: Counter = Counter()

    def __call__(self, target, remote_argv, *, timeout_seconds):
        assert target == self.host, f"ssh target {target!r} != {self.host!r}"
        assert timeout_seconds > 0
        if self.fail is not None:
            return watch.CommandArtifact(returncode=None, error=self.fail)
        if tuple(remote_argv) == ("id", "-u"):
            return watch.CommandArtifact(returncode=0, stdout=f"{self.uid}\n")
        if tuple(remote_argv) == ("launchctl", "list"):
            lines = "PID\tStatus\tLabel\n" + "".join(
                f"-\t1\t{label}\n" for label in self.jobs
            )
            return watch.CommandArtifact(returncode=0, stdout=lines)
        if len(remote_argv) == 3 and tuple(remote_argv[:2]) == ("launchctl", "print"):
            label = remote_argv[2].split("/", 2)[2]
            assert label in self.jobs, f"print for undiscovered label {label!r}"
            runs, exit_code = self.jobs[label](self._calls[label])
            self._calls[label] += 1
            return _print_artifact(self.uid, label, runs=runs, exit_code=exit_code)
        raise AssertionError(f"unexpected remote invocation: {remote_argv!r}")


def _advance_per_tick(step: int = 2, exit_code: int = 1, start_runs: int = 90):
    """Job whose run counter advances by ``step`` with a fixed exit code."""

    def job(call_index: int) -> tuple[int, int]:
        return start_runs + step * call_index, exit_code

    return job


def _patch_local_capture(
    monkeypatch: pytest.MonkeyPatch,
    labels: tuple[str, ...] = (LOCAL_FIXTURE_LABEL,),
    job_state=None,
) -> None:
    """Stub the local host's launchctl while letting real remote code run.

    The local job is healthy and stable unless ``job_state`` supplies a
    ``callable(call_index) -> (runs, exit_code)``.
    """

    real_capture = watch.capture_launchctl_artifacts
    calls: Counter = Counter()

    def fake_capture(*, uid, timeout_seconds, label_prefix, host=None):
        if host is not None:
            return real_capture(uid=uid, timeout_seconds=timeout_seconds, label_prefix=label_prefix, host=host)
        artifacts = {}
        for label in labels:
            if job_state is None:
                runs, exit_code = 10, 0
            else:
                runs, exit_code = job_state(calls[label])
                calls[label] += 1
            artifacts[label] = _print_artifact(uid, label, runs=runs, exit_code=exit_code)
        return tuple(sorted(labels)), artifacts

    monkeypatch.setattr(watch, "capture_launchctl_artifacts", fake_capture)


class TestRemoteHostChecks:
    """A HOST THAT CANNOT BE SEEN MUST NEVER REPORT CALM.

    The failure this prevents: a machine everyone believes is retired still
    answers ping and still runs a nightly backup that exits 1, for months, and
    nobody is told because nothing is watching it. An unreachable host is
    UNKNOWN (exit 3), never a clean run.
    """

    def test_remote_crash_loop_is_reported_with_host_named(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """POSITIVE CONTROL: a remote crash loop must actually fire the watch."""
        stub = _RemoteSshStub(jobs={REMOTE_CRASH_LABEL: _advance_per_tick()})
        monkeypatch.setattr(watch, "_run_ssh", stub)
        _patch_local_capture(monkeypatch)
        config = watch.WatchConfig(
            hosts=("remote-mac",),
            state_path=tmp_path / "state.json",
            no_alert=True,
            fail_on_crash_loop=True,
        )

        for now in (1_000.0, 1_060.0, 1_120.0, 1_180.0):
            report, exit_code = watch.run_once(config, now=now)

        assert exit_code == 1, (
            f"a remote crash loop must exit 1 with --fail-on-crash-loop; "
            f"summary={report['summary']}"
        )
        assert report["summary"]["crash_looping"] == [f"remote-mac/{REMOTE_CRASH_LABEL}"], (
            "the finding must name the host it was observed on"
        )
        job_rows = {
            job["label"]: job for job in report["jobs"] if job.get("host") == "remote-mac"
        }
        assert job_rows[REMOTE_CRASH_LABEL]["verdict"] == "crash_looping"
        assert job_rows[REMOTE_CRASH_LABEL]["respawn_restart_evidence"][
            "observed_nonzero_exit_count"
        ] >= config.threshold
        # The local clean run must not downgrade the remote finding.
        assert report["summary"]["coverage_complete"] is True

    def test_remote_crash_loop_state_is_host_qualified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The watcher and the remote both run com.example.browser: baselines must not mix."""
        stub = _RemoteSshStub(jobs={LOCAL_FIXTURE_LABEL: _advance_per_tick()})
        monkeypatch.setattr(watch, "_run_ssh", stub)
        _patch_local_capture(monkeypatch)
        config = watch.WatchConfig(
            hosts=("remote-mac",),
            state_path=tmp_path / "state.json",
            no_alert=True,
            fail_on_crash_loop=True,
        )

        for now in (1_000.0, 1_060.0, 1_120.0, 1_180.0):
            report, _ = watch.run_once(config, now=now)

        assert report["summary"]["crash_looping"] == [
            f"remote-mac/{LOCAL_FIXTURE_LABEL}"
        ], "only the REMOTE same-named job may be flagged; the local one is healthy"
        state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
        assert f"remote-mac/{LOCAL_FIXTURE_LABEL}" in state["jobs"], (
            "remote baselines must be stored host-qualified"
        )
        assert LOCAL_FIXTURE_LABEL in state["jobs"], (
            "the local same-named baseline must survive untouched"
        )
        assert state["jobs"][f"remote-mac/{LOCAL_FIXTURE_LABEL}"]["last_runs"] != state[
            "jobs"
        ][LOCAL_FIXTURE_LABEL]["last_runs"], (
            "shared state for two hosts running one label corrupts both run counters"
        )

    def test_remote_crash_loop_pages_with_the_remote_host_named(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stub = _RemoteSshStub(jobs={REMOTE_CRASH_LABEL: _advance_per_tick()})
        monkeypatch.setattr(watch, "_run_ssh", stub)
        _patch_local_capture(monkeypatch)
        pages: list[dict] = []

        def fake_crash_loop(**kwargs):
            pages.append(kwargs)
            return SimpleNamespace(success=True)

        monkeypatch.setattr(watch, "alert_crash_loop", fake_crash_loop)
        config = watch.WatchConfig(
            hosts=("remote-mac",),
            state_path=tmp_path / "state.json",
            fail_on_crash_loop=True,
        )

        for now in (1_000.0, 1_060.0, 1_120.0, 1_180.0):
            watch.run_once(config, now=now)

        assert len(pages) == 1, "one new incident must page exactly once"
        assert pages[0]["host"] == "remote-mac", (
            "the page must name the host the loop runs on, not the watcher"
        )
        assert pages[0]["label"] == REMOTE_CRASH_LABEL

    def test_unreachable_remote_host_is_unknown_and_exits_3(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stub = _RemoteSshStub(fail="ssh remote-mac timed out after 20s")
        monkeypatch.setattr(watch, "_run_ssh", stub)
        _patch_local_capture(monkeypatch)
        pages: list[dict] = []

        def fake_alert(**kwargs):
            pages.append(kwargs)
            return SimpleNamespace(success=True)

        monkeypatch.setattr(watch, "alert", fake_alert)
        config = watch.WatchConfig(
            hosts=("remote-mac",),
            state_path=tmp_path / "state.json",
        )

        report, exit_code = watch.run_once(config, now=1_000.0)

        assert exit_code == 3, (
            f"an unreachable remote host must exit 3, never clean: {report['summary']}"
        )
        assert report["summary"]["unreachable_hosts"] == ["remote-mac"]
        assert report["summary"]["unknown"] == ["remote-mac/<launchd-discovery>"]
        assert report["summary"]["crash_looping"] == []
        assert report["summary"]["coverage_complete"] is False
        # A host nobody can see must page, not just write a log line; that
        # silence-for-months pattern IS the incident this watch exists about.
        assert len(pages) == 1, "an unreachable remote host must page"
        assert pages[0]["dedupe_key"] == "launchd-crash-loop-watch/unreachable/remote-mac"
        assert "remote-mac" in pages[0]["summary"]
        assert pages[0]["severity"] == "critical", (
            "an unmeasurable host must page as critical, not as a low-severity "
            "note that nobody reads"
        )

    def test_unreachable_remote_is_not_downgraded_by_a_local_crash_loop(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stub = _RemoteSshStub(fail="connection refused")
        monkeypatch.setattr(watch, "_run_ssh", stub)
        _patch_local_capture(monkeypatch, job_state=_advance_per_tick())
        config = watch.WatchConfig(
            hosts=("remote-mac",),
            state_path=tmp_path / "state.json",
            no_alert=True,
            fail_on_crash_loop=True,
        )

        exit_code = 0
        for now in (1_000.0, 1_060.0, 1_120.0, 1_180.0):
            report, exit_code = watch.run_once(config, now=now)

        assert exit_code == 3, (
            "UNKNOWN (cannot measure) dominates a detected crash loop: the "
            "unmeasurable host is the louder condition and must not read as 1"
        )
        assert report["summary"]["unreachable_hosts"] == ["remote-mac"]
        assert any(
            entry.endswith(f"/{LOCAL_FIXTURE_LABEL}")
            for entry in report["summary"]["crash_looping"]
        )

    def test_unparseable_remote_inventory_is_unknown_not_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def garbage_ssh(target, remote_argv, *, timeout_seconds):
            if tuple(remote_argv) == ("id", "-u"):
                return watch.CommandArtifact(returncode=0, stdout=f"{REMOTE_UID}\n")
            return watch.CommandArtifact(returncode=0, stdout="not launchctl output\n")

        monkeypatch.setattr(watch, "_run_ssh", garbage_ssh)
        _patch_local_capture(monkeypatch)
        config = watch.WatchConfig(
            hosts=("remote-mac",),
            state_path=tmp_path / "state.json",
            no_alert=True,
        )

        report, exit_code = watch.run_once(config, now=1_000.0)

        assert exit_code == 3, "unparseable remote output must exit 3, never clean"
        assert report["summary"]["unreachable_hosts"] == ["remote-mac"]

    def test_clean_remote_host_produces_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        label = "com.example.repl"
        stub = _RemoteSshStub(jobs={label: lambda _n: (8_344, 0)})
        monkeypatch.setattr(watch, "_run_ssh", stub)
        _patch_local_capture(monkeypatch)
        config = watch.WatchConfig(
            hosts=("remote-mac",),
            state_path=tmp_path / "state.json",
            no_alert=True,
            fail_on_crash_loop=True,
        )

        for now in (1_000.0, 1_060.0):
            report, exit_code = watch.run_once(config, now=now)

        assert exit_code == 0
        assert report["summary"]["crash_looping"] == []
        assert report["summary"]["unknown"] == []
        assert report["summary"]["unreachable_hosts"] == []
        assert report["summary"]["coverage_complete"] is True

    def test_local_only_path_never_touches_ssh_and_keeps_report_shape(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def forbidden_ssh(*args, **kwargs):
            pytest.fail("the local-only watch must not invoke ssh")

        monkeypatch.setattr(watch, "_run_ssh", forbidden_ssh)
        _patch_local_capture(monkeypatch)
        config = watch.WatchConfig(
            state_path=tmp_path / "state.json",
            no_alert=True,
        )

        report, exit_code = watch.run_once(config, now=1_000.0)

        assert exit_code == 0
        assert "hosts" not in report, "the local-only report shape is unchanged"
        assert set(report["summary"]) == {
            "total",
            "by_verdict",
            "crash_looping",
            "unknown",
            "coverage_complete",
            "error_count",
        }
        assert all("host" not in job for job in report["jobs"])
        state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
        assert list(state["jobs"]) == [LOCAL_FIXTURE_LABEL], (
            "local state keys stay un-prefixed, exactly as historical builds wrote them"
        )

    def test_run_ssh_uses_batch_mode_and_bounded_timeouts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["timeout"] = kwargs["timeout"]
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(watch.subprocess, "run", fake_run)
        artifact = watch._run_ssh("remote-mac", ("launchctl", "list"), timeout_seconds=10.0)

        assert captured["cmd"] == [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "remote-mac",
            "launchctl",
            "list",
        ], "BatchMode must prevent a password prompt hanging the watch"
        assert captured["timeout"] == 20.0
        assert artifact.returncode == 0


def test_remote_host_names_are_validated() -> None:
    with pytest.raises(ValueError, match="whitespace"):
        watch.WatchConfig(hosts=("bad host",))
    with pytest.raises(ValueError, match="'/'"):
        watch.WatchConfig(hosts=("bad/host",))
    with pytest.raises(ValueError, match="duplicate"):
        watch.WatchConfig(hosts=("remote-mac", "remote-mac"))


# --- Remote-only mode and evidence preservation -------------------------------


def test_remote_only_skips_the_local_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dedicated per-remote job must not re-classify the watching machine's jobs.

    Without the main watcher's nonzero-findings exemptions, an additive pass
    over the local jobs would page false crash loops for exempted findings jobs.
    """

    real_capture = watch.capture_launchctl_artifacts

    def forbidden_local_capture(*, uid, timeout_seconds, label_prefix, host=None):
        if host is None:
            pytest.fail("--remote-only must not run the local launchctl pass")
        return real_capture(uid=uid, timeout_seconds=timeout_seconds, label_prefix=label_prefix, host=host)

    monkeypatch.setattr(watch, "capture_launchctl_artifacts", forbidden_local_capture)
    stub = _RemoteSshStub(
        jobs={"com.example.repl": lambda _n: (8_344, 0)}
    )
    monkeypatch.setattr(watch, "_run_ssh", stub)
    config = watch.WatchConfig(
        hosts=("remote-mac",),
        remote_only=True,
        state_path=tmp_path / "state.json",
        no_alert=True,
    )

    report, exit_code = watch.run_once(config, now=1_000.0)

    assert exit_code == 0
    assert report["hosts"] == ["remote-mac"]
    assert all(job.get("host") == "remote-mac" for job in report["jobs"])
    assert report["summary"]["coverage_complete"] is True

    # And the UNKNOWN convention still holds in remote-only mode.
    stub.fail = "ssh remote-mac timed out after 20s"
    report, exit_code = watch.run_once(config, now=1_060.0)
    assert exit_code == 3
    assert report["summary"]["unreachable_hosts"] == ["remote-mac"]


def test_remote_only_requires_a_host() -> None:
    with pytest.raises(ValueError, match="requires at least one --host"):
        watch.WatchConfig(remote_only=True)
    with pytest.raises(ValueError, match="requires at least one --host"):
        watch._parse_args(["--label-prefix", PREFIX, "--remote-only"])


def test_ssh_flap_preserves_remote_crash_loop_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One missed ssh round trip must not wipe an accumulating baseline.

    A host whose ssh fails every other tick could never reach
    the crash-loop threshold, because each failed tick saved a state file
    without that host's evidence. The local-only path preserves state by
    never saving on discovery failure; the remote path must match.
    """
    stub = _RemoteSshStub(jobs={REMOTE_CRASH_LABEL: _advance_per_tick()})
    monkeypatch.setattr(watch, "_run_ssh", stub)
    _patch_local_capture(monkeypatch)
    config = watch.WatchConfig(
        hosts=("remote-mac",),
        state_path=tmp_path / "state.json",
        no_alert=True,
        fail_on_crash_loop=True,
    )

    report, exit_code = watch.run_once(config, now=1_000.0)  # baseline
    assert exit_code == 0
    report, exit_code = watch.run_once(config, now=1_060.0)  # event 1
    assert exit_code == 0

    stub.fail = "ssh remote-mac timed out after 20s"
    report, exit_code = watch.run_once(config, now=1_120.0)  # flap: UNKNOWN
    assert exit_code == 3
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    preserved = state["jobs"][f"remote-mac/{REMOTE_CRASH_LABEL}"]
    assert len(preserved["nonzero_exit_events"]) == 1, (
        "the failed tick's save wiped the accumulating evidence; a flapping "
        "host can never reach threshold that way"
    )

    stub.fail = None
    report, exit_code = watch.run_once(config, now=1_180.0)  # event 2
    assert exit_code == 0
    report, exit_code = watch.run_once(config, now=1_240.0)  # event 3: loop
    assert report["summary"]["crash_looping"] == [f"remote-mac/{REMOTE_CRASH_LABEL}"]
    assert exit_code == 1, (
        "crash-loop detection must survive a missed tick on the target host"
    )


# --- Transport failure after discovery -----------------------------------------


def test_remote_print_transport_failure_after_discovery_is_unknown_and_pages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """id and list succeed, then EVERY print dies mid-loop (connection reset).

    As per-job unknowns with no host-level page, a host that gave no measurable
    inventory would leave only a log line: the silence this watch exists to end.
    """

    def flaky_ssh(target, remote_argv, *, timeout_seconds):
        if tuple(remote_argv) == ("id", "-u"):
            return watch.CommandArtifact(returncode=0, stdout=f"{REMOTE_UID}\n")
        if tuple(remote_argv) == ("launchctl", "list"):
            return watch.CommandArtifact(
                returncode=0,
                stdout=f"PID\tStatus\tLabel\n-\t1\t{REMOTE_CRASH_LABEL}\n",
            )
        return watch.CommandArtifact(
            returncode=255, stderr="Connection reset by peer"
        )

    monkeypatch.setattr(watch, "_run_ssh", flaky_ssh)
    _patch_local_capture(monkeypatch)
    pages: list[dict] = []
    monkeypatch.setattr(
        watch,
        "alert",
        lambda **kwargs: (
            pages.append(kwargs),
            SimpleNamespace(success=True),
        )[1],
    )
    config = watch.WatchConfig(
        hosts=("remote-mac",),
        state_path=tmp_path / "state.json",
    )

    report, exit_code = watch.run_once(config, now=1_000.0)

    assert exit_code == 3
    assert report["summary"]["unreachable_hosts"] == ["remote-mac"]
    assert report["summary"]["unknown"] == ["remote-mac/<launchd-discovery>"]
    assert len(pages) == 1, (
        "a remote host whose every per-job print fails gave no measurable "
        "inventory and must page, not just log"
    )
    assert pages[0]["severity"] == "critical"


def test_local_discovery_flap_preserves_local_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """In additive mode a local discovery flap must not wipe the local host's
    evidence slice at the next save, or local crash-loop detection could never
    accumulate across a flapping tick."""
    real_capture = watch.capture_launchctl_artifacts
    local_fail = {"on": False}
    calls: Counter = Counter()

    def local_capture(*, uid, timeout_seconds, label_prefix, host=None):
        if host is not None:
            return real_capture(uid=uid, timeout_seconds=timeout_seconds, label_prefix=label_prefix, host=host)
        if local_fail["on"]:
            raise watch.LaunchdDiscoveryError("launchctl list timed out after 10s")
        label = LOCAL_FIXTURE_LABEL
        runs, exit_code = 90 + 2 * calls[label], 1
        calls[label] += 1
        return (label,), {
            label: _print_artifact(uid, label, runs=runs, exit_code=exit_code)
        }

    monkeypatch.setattr(watch, "capture_launchctl_artifacts", local_capture)
    stub = _RemoteSshStub(jobs={"com.example.repl": lambda _n: (8_344, 0)})
    monkeypatch.setattr(watch, "_run_ssh", stub)
    config = watch.WatchConfig(
        hosts=("remote-mac",),
        state_path=tmp_path / "state.json",
        no_alert=True,
        fail_on_crash_loop=True,
    )

    _, exit_code = watch.run_once(config, now=1_000.0)  # local baseline
    assert exit_code == 0
    _, exit_code = watch.run_once(config, now=1_060.0)  # local event 1
    assert exit_code == 0

    local_fail["on"] = True
    report, exit_code = watch.run_once(config, now=1_120.0)  # local flap
    assert exit_code == 3, "a local discovery failure is UNKNOWN, exit 3"
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    preserved = state["jobs"][LOCAL_FIXTURE_LABEL]
    assert len(preserved["nonzero_exit_events"]) == 1, (
        "the local flap's save wiped the accumulating evidence"
    )

    local_fail["on"] = False
    _, exit_code = watch.run_once(config, now=1_180.0)  # local event 2
    assert exit_code == 0
    report, exit_code = watch.run_once(config, now=1_240.0)  # local event 3
    assert any(
        entry.endswith(f"/{LOCAL_FIXTURE_LABEL}")
        for entry in report["summary"]["crash_looping"]
    ), "local crash-loop detection must survive its own discovery flap"
    assert exit_code == 1


# --- the crash-loop page itself --------------------------------------------------------------


def test_crash_loop_page_rejects_incomplete_evidence() -> None:
    from honest_watchdogs.alerts import AlertConfigError

    good = dict(label="com.example.x", exit_code=1, observed_nonzero_exit_count=3,
                window_seconds=600, runs_advanced=3)
    for override in ({"label": " "}, {"exit_code": 0}, {"observed_nonzero_exit_count": 1},
                     {"window_seconds": 0}, {"runs_advanced": 2}):
        with pytest.raises(AlertConfigError):
            watch.alert_crash_loop(**{**good, **override})


def test_crash_loop_pages_from_two_hosts_are_not_deduped_together(monkeypatch) -> None:
    """Two machines can run the same label; a label-only key would swallow the second page."""
    monkeypatch.setenv("WATCHDOG_ALERT_SINKS", "stdout")
    args = dict(label="com.example.browser", exit_code=1, observed_nonzero_exit_count=3,
                window_seconds=600, runs_advanced=3)
    first = watch.alert_crash_loop(host="host-a", **args)
    second = watch.alert_crash_loop(host="host-b", **args)
    assert first.dedupe_key != second.dedupe_key
    assert first.delivered and second.delivered
    assert "[host-b]" in second.summary and "exit code 1" in second.summary


def test_cli_requires_a_label_prefix(capsys) -> None:
    assert watch.main([]) == 2
    assert "--label-prefix" in capsys.readouterr().err


@pytest.mark.parametrize("hosts", [(), ("remote-mac",)])
def test_a_corrupt_state_file_is_unknown_and_left_untouched(tmp_path, monkeypatch, hosts) -> None:
    """MUST-FIRE, in local and multi-host mode: exit 3, and the corrupt file is not replaced."""
    state_path = tmp_path / "state.json"
    state_path.write_text("{not-json\n")
    _patch_local_capture(monkeypatch)
    monkeypatch.setattr(watch, "_run_ssh", _RemoteSshStub(jobs={"com.example.repl": lambda _n: (5, 0)}))
    config = watch.WatchConfig(hosts=hosts, state_path=state_path, no_alert=True)
    _report, exit_code = watch.run_once(config, now=1_000.0)
    assert exit_code == 3
    assert state_path.read_text() == "{not-json\n"


def test_json_flag_prints_the_report_even_when_healthy(tmp_path, monkeypatch, capsys) -> None:
    _patch_local_capture(monkeypatch)
    code = watch.main(["--label-prefix", PREFIX, "--json", "--no-alert",
                       "--state-file", str(tmp_path / "state.json")])
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["summary"]["coverage_complete"] is True
    assert captured.err == "", "--json prints no human table"
