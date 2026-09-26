"""Tests for the launchd wedge detector.

The load-bearing pair: an hourly one-shot alive 16h31m is WEDGED; a KeepAlive daemon alive 23h
is HEALTHY. They are indistinguishable by uptime and trivially distinguishable by plist. A
detector that cannot reproduce the incident it was written for is not a detector.
"""

from __future__ import annotations

import json
import plistlib
from types import SimpleNamespace

from honest_watchdogs import wedge_watch as ww
from honest_watchdogs.wedge_watch import Job, classify, parse_etime, period_seconds


def _job(label: str, elapsed_s: int, plist: dict) -> Job:
    return Job(label=label, pid=1, elapsed_s=elapsed_s, plist=plist)


# --- the pair that motivates the tool -------------------------------------------------------


def test_the_hourly_one_shot_alive_sixteen_hours_is_wedged() -> None:
    f = classify(_job("com.example.jobs.hourly-scrape", 16 * 3600 + 31 * 60, {"StartInterval": 3600}))
    assert f is not None and f.kind == "wedged"
    assert "HALTED" in f.detail


def test_the_keepalive_daemon_alive_a_day_is_not_flagged() -> None:
    assert classify(_job("com.example.web", 23 * 3600, {"KeepAlive": True})) is None


def test_uptime_alone_cannot_separate_them() -> None:
    """The control for the control: 23h healthy > 16h broken, so uptime is not the signal."""
    daemon = classify(_job("d", 23 * 3600, {"KeepAlive": True}))
    oneshot = classify(_job("o", 16 * 3600, {"StartInterval": 3600}))
    assert daemon is None and oneshot is not None


# --- bounds ---------------------------------------------------------------------------------


def test_a_run_inside_its_period_is_clean() -> None:
    assert classify(_job("x", 600, {"StartInterval": 3600})) is None


def test_slack_is_allowed_before_calling_it_wedged() -> None:
    """A false page is how a watch gets muted; 1.2x period must not fire, 1.6x must."""
    assert classify(_job("x", int(3600 * 1.2), {"StartInterval": 3600})) is None
    assert classify(_job("x", int(3600 * 1.6), {"StartInterval": 3600})) is not None


def test_two_hourly_calendar_schedule() -> None:
    plist = {"StartCalendarInterval": [{"Hour": h, "Minute": 30} for h in range(0, 24, 2)]}
    assert period_seconds(plist) == 7200
    assert classify(_job("t", 3 * 3600 + 50 * 60, plist)) is not None


def test_a_daily_job_uses_the_ceiling_not_a_day_and_a_half() -> None:
    plist = {"StartCalendarInterval": [{"Hour": 3, "Minute": 0}]}
    assert period_seconds(plist) == 24 * 3600
    assert classify(_job("d", 25 * 3600, plist)) is not None


def test_minute_only_schedule_is_hourly() -> None:
    assert period_seconds({"StartCalendarInterval": [{"Minute": 15}]}) == 3600


def test_calendar_wraps_midnight() -> None:
    """23:30 and 00:30 are 60 minutes apart, not 1380."""
    plist = {"StartCalendarInterval": [{"Hour": 23, "Minute": 30}, {"Hour": 0, "Minute": 30}]}
    assert period_seconds(plist) == 3600


# --- unknowns must never read as clean -----------------------------------------------------


def test_unreadable_plist_is_unknown_not_clean() -> None:
    f = classify(_job("x", 99999, {}))
    assert f is not None and f.kind == "unknown"


def test_no_schedule_and_no_keepalive_is_unknown() -> None:
    f = classify(_job("x", 99999, {"ProgramArguments": ["/bin/true"]}))
    assert f is not None and f.kind == "unknown"


def test_schedule_plus_keepalive_is_unknown_not_wedged() -> None:
    f = classify(_job("x", 99999, {"StartInterval": 60, "KeepAlive": {"SuccessfulExit": False}}))
    assert f is not None and f.kind == "unknown"


def test_a_wedged_job_cannot_enlarge_its_own_bound() -> None:
    """The period comes from the DECLARED schedule, never from observed runtime."""
    assert period_seconds({"StartInterval": 3600}) == 3600


def test_etime_formats() -> None:
    assert parse_etime("09:18") == 558
    assert parse_etime("16:32:30") == 16 * 3600 + 32 * 60 + 30
    assert parse_etime("22-19:01:43") == 22 * 86400 + 19 * 3600 + 60 + 43
    assert parse_etime("") is None
    assert parse_etime("garbage") is None


# --- a declared runtime beats a cadence ----------------------------------------------------
#
# A daily job gets a 24h cadence bound. If the job itself expects to finish in ten minutes, a
# two-hour hang has already halted its schedule long before the cadence bound notices.


def _plist_with_script(tmp_path, body: str, schedule: dict) -> dict:
    script = tmp_path / "job.sh"
    script.write_text(body, encoding="utf-8")
    return {"ProgramArguments": ["/bin/bash", str(script)], **schedule}


def test_daily_job_that_declares_its_runtime_is_flagged_long_before_24h(tmp_path) -> None:
    plist = _plist_with_script(tmp_path, "#!/bin/bash\necho 'starting (expect ~10 min)'\n",
                               {"StartCalendarInterval": [{"Hour": 0, "Minute": 30}]})
    finding = classify(Job(label="com.example.daily", pid=1, elapsed_s=7596, plist=plist))
    assert finding is not None and finding.kind == "wedged"
    assert "DECLARED" in finding.detail
    cadence_bound = min(int(86400 * ww.WEDGE_MULTIPLE), ww.ABSOLUTE_CEILING_S)
    assert 7596 < cadence_bound, "if the cadence bound already caught this, the test proves nothing"


def test_no_declared_runtime_falls_back_and_says_it_is_weak(tmp_path) -> None:
    plist = _plist_with_script(tmp_path, "#!/bin/bash\necho hello\n", {"StartInterval": 3600})
    finding = classify(Job(label="com.example.hourly", pid=1, elapsed_s=7200, plist=plist))
    assert finding is not None and finding.kind == "wedged"
    assert "FALLBACK" in finding.detail


def test_a_declared_runtime_does_not_manufacture_a_false_wedge(tmp_path) -> None:
    plist = _plist_with_script(tmp_path, "#!/bin/bash\necho 'archive (expect ~57 min)'\n",
                               {"StartCalendarInterval": [{"Weekday": 0, "Hour": 2}]})
    assert classify(Job(label="com.example.weekly", pid=1, elapsed_s=57 * 60, plist=plist)) is None


def test_declared_runtime_reads_the_script_not_the_interpreter(tmp_path) -> None:
    plist = _plist_with_script(tmp_path, "#!/bin/bash\n# expect ~5 min\n", {"StartInterval": 86400})
    plist["ProgramArguments"] = ["/usr/bin/env", "python3"] + plist["ProgramArguments"][1:]
    assert ww.declared_runtime_seconds(plist) == 300


def test_an_unreadable_script_falls_back_rather_than_crashing(tmp_path) -> None:
    """Unreadable means UNKNOWN runtime, not zero; zero would page everything."""
    plist = {"ProgramArguments": ["/bin/bash", str(tmp_path / "missing.sh")], "StartInterval": 3600}
    assert ww.declared_runtime_seconds(plist) is None
    assert classify(Job(label="x", pid=1, elapsed_s=10, plist=plist)) is None


# --- collection through a fake runner ------------------------------------------------------


def _fake_runner(listing: str, etimes: dict[str, object], *, list_rc: int = 0):
    """``etimes`` maps a pid to its ps output, or to an ``(rc, output)`` pair.

    A pid missing from ``etimes`` behaves like real ``ps -p`` for a process that has exited:
    exit 1, no output.
    """

    def run(argv):
        if list(argv) == ["launchctl", "list"]:
            return list_rc, listing
        if list(argv[:3]) == ["ps", "-o", "etime="]:
            value = etimes.get(argv[-1])
            if value is None:
                return 1, ""
            return value if isinstance(value, tuple) else (0, value)
        raise AssertionError(argv)
    return run


def test_collect_reads_the_plist_for_each_running_prefixed_job(tmp_path) -> None:
    (tmp_path / "com.example.hourly.plist").write_bytes(plistlib.dumps({"StartInterval": 3600}))
    listing = ("PID\tStatus\tLabel\n"
               "501\t0\tcom.example.hourly\n"
               "-\t0\tcom.example.idle\n"
               "777\t0\tcom.vendor.other\n")
    jobs, problems = ww.collect(tmp_path, "com.example.", runner=_fake_runner(listing, {"501": "16:31:00"}))
    assert problems == []
    assert [(j.label, j.elapsed_s, j.plist) for j in jobs] == [
        ("com.example.hourly", 16 * 3600 + 31 * 60, {"StartInterval": 3600})
    ]


def test_a_process_that_exited_before_ps_is_not_a_fault(tmp_path) -> None:
    listing = "PID\tStatus\tLabel\n501\t0\tcom.example.hourly\n"
    jobs, problems = ww.collect(tmp_path, "com.example.", runner=_fake_runner(listing, {}))
    assert jobs == [] and problems == []


def test_a_failing_ps_makes_the_job_unknown_not_dropped(tmp_path) -> None:
    """MUST-FIRE: ps timing out, missing, or failing is 'could not measure', never 'exited'."""
    listing = "PID\tStatus\tLabel\n501\t0\tcom.example.hourly\n"
    for ps_result in ((-1, ""), (127, ""), (1, "ps: permission denied"), (0, "garbage")):
        jobs, problems = ww.collect(
            tmp_path, "com.example.", runner=_fake_runner(listing, {"501": ps_result})
        )
        assert jobs == [], ps_result
        assert [(p.label, p.kind) for p in problems] == [("com.example.hourly", "unknown")], ps_result


def test_a_failing_ps_makes_the_survey_exit_3(tmp_path, monkeypatch) -> None:
    listing = "PID\tStatus\tLabel\n501\t0\tcom.example.hourly\n"
    monkeypatch.setattr(ww, "run_command", _fake_runner(listing, {"501": (-1, "")}))
    real_collect = ww.collect
    monkeypatch.setattr(
        ww, "collect", lambda d, p: real_collect(d, p, runner=ww.run_command)
    )
    assert ww.main(["--label-prefix", "com.example.", "--no-alert"]) == 3


def test_a_failing_launchctl_list_is_unknown(tmp_path) -> None:
    jobs, problems = ww.collect(
        tmp_path, "com.example.", runner=_fake_runner("PID\tStatus\tLabel\n", {}, list_rc=1)
    )
    assert jobs == [] and problems[0].kind == "unknown"


def test_collect_with_an_empty_listing_is_unknown(tmp_path) -> None:
    jobs, problems = ww.collect(tmp_path, "com.example.", runner=_fake_runner("", {}))
    assert jobs == [] and problems[0].kind == "unknown"


def test_a_prefix_that_matches_nothing_is_unknown_not_clean(tmp_path) -> None:
    listing = "PID\tStatus\tLabel\n501\t0\tcom.vendor.other\n"
    jobs, problems = ww.collect(tmp_path, "com.exmaple.", runner=_fake_runner(listing, {}))
    assert jobs == []
    assert problems and problems[0].kind == "unknown" and "matches" in problems[0].detail


def test_loaded_but_idle_jobs_are_coverage_not_a_problem(tmp_path) -> None:
    listing = "PID\tStatus\tLabel\n-\t0\tcom.example.hourly\n"
    jobs, problems = ww.collect(tmp_path, "com.example.", runner=_fake_runner(listing, {}))
    assert jobs == [] and problems == []


def test_a_job_without_a_plist_file_is_unknown(tmp_path) -> None:
    listing = "PID\tStatus\tLabel\n42\t0\tcom.example.ghost\n"
    jobs, _ = ww.collect(tmp_path, "com.example.", runner=_fake_runner(listing, {"42": "01:00"}))
    assert classify(jobs[0]).kind == "unknown"


# --- delivery and exit codes ---------------------------------------------------------------


def test_the_renag_latch_advances_only_on_successful_delivery(tmp_path, monkeypatch) -> None:
    calls: list[str] = []
    outcome = {"success": False}

    def fake_alert(severity, component, summary, **kwargs):
        calls.append(kwargs["dedupe_key"])
        return SimpleNamespace(success=outcome["success"])

    monkeypatch.setattr(ww, "alert", fake_alert)
    finding = ww.Finding("com.example.hourly", "wedged", "stuck")
    state = tmp_path / "state.json"

    assert ww.deliver([finding], state, now=1000.0) == 0
    assert ww.deliver([finding], state, now=1060.0) == 0
    assert len(calls) == 2, "a failed alert must stay due, not consume the re-nag window"

    outcome["success"] = True
    assert ww.deliver([finding], state, now=1120.0) == 1
    assert ww.deliver([finding], state, now=1180.0) == 0
    assert len(calls) == 3, "a delivered alert must not repeat inside the re-nag window"
    assert json.loads(state.read_text())[ww.dedupe_key_for("wedged", "com.example.hourly")] == 1120.0


def test_label_prefix_is_required(capsys) -> None:
    assert ww.main([]) == 2
    assert "--label-prefix" in capsys.readouterr().err


def test_exit_codes_unknown_outranks_wedged(tmp_path, monkeypatch) -> None:
    def fake_collect(agents_dir, prefix):
        return [Job("com.example.a", 1, 99999, {"StartInterval": 60})], [
            ww.Finding("(all)", "unknown", "partial survey")
        ]

    monkeypatch.setattr(ww, "collect", fake_collect)
    assert ww.main(["--label-prefix", "com.example.", "--no-alert"]) == 3

    monkeypatch.setattr(ww, "collect",
                        lambda d, p: ([Job("com.example.a", 1, 99999, {"StartInterval": 60})], []))
    assert ww.main(["--label-prefix", "com.example.", "--no-alert"]) == 1

    monkeypatch.setattr(ww, "collect", lambda d, p: ([], []))
    assert ww.main(["--label-prefix", "com.example.", "--no-alert", "--json"]) == 0


def test_a_corrupt_state_file_is_unknown_and_left_untouched(tmp_path, monkeypatch) -> None:
    """MUST-FIRE: a broken latch record must not be silently reset to a clean one."""
    state = tmp_path / "state.json"
    state.write_text("{not json")
    monkeypatch.setattr(ww, "collect", lambda d, p: ([], []))
    code = ww.main(["--label-prefix", "com.example.", "--state-file", str(state)])
    assert code == 3, "a corrupt state file must be exit 3 even when nothing is wedged"
    assert state.read_text() == "{not json", "the corrupt file must be preserved for inspection"


def test_a_corrupt_state_file_still_sends_the_alert(tmp_path, monkeypatch) -> None:
    """Silence is worse than repetition: findings are alerted, just not latched."""
    state = tmp_path / "state.json"
    state.write_text("[]")
    sent = []
    monkeypatch.setattr(ww, "alert", lambda *a, **k: (sent.append(k["dedupe_key"]),
                                                       SimpleNamespace(success=True))[1])
    monkeypatch.setattr(ww, "collect", lambda d, p: (
        [Job("com.example.a", 1, 99999, {"StartInterval": 60})], []))
    assert ww.main(["--label-prefix", "com.example.", "--state-file", str(state)]) == 3
    assert sent == [ww.dedupe_key_for("wedged", "com.example.a")]
    assert state.read_text() == "[]"
