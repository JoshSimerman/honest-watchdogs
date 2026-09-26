"""Tests for the systemd timer liveness detector.

The ssh/local transport is faked at ``run_remote``; every command the detector would send is
matched exactly, so a change to the command shape fails loudly here.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from honest_watchdogs import timer_liveness as watch

HOST = "timers-host"


LIST_ONE = """\
Sun 2027-09-19 09:00:00 UTC 20min Sun 2027-09-19 08:00:00 UTC 40min ago billing.timer billing.service
"""

HOURLY_CALENDAR = """\
  Original form: hourly
Normalized form: *-*-* *:00:00
    Next elapse: Sun 2027-09-19 09:00:00 UTC
       From now: 20min left
   Iteration #2: Sun 2027-09-19 10:00:00 UTC
       From now: 1h 20min left
   Iteration #3: Sun 2027-09-19 11:00:00 UTC
       From now: 2h 20min left
"""


def hourly_calendar(start_hour: int) -> str:
    hours = (start_hour, start_hour + 1, start_hour + 2)
    return "\n".join(
        [
            f"    Next elapse: Sun 2027-09-19 {hours[0]:02d}:00:00 UTC",
            f"   Iteration #2: Sun 2027-09-19 {hours[1]:02d}:00:00 UTC",
            f"   Iteration #3: Sun 2027-09-19 {hours[2]:02d}:00:00 UTC",
        ]
    )


def hourly_after(base: int) -> str:
    first = (base // 3600 + 1) * 3600
    labels = ("    Next elapse", "   Iteration #2", "   Iteration #3")
    return "\n".join(
        f"{label}: {datetime.fromtimestamp(first + 3600 * i, UTC):%a %Y-%m-%d %H:%M:%S} UTC"
        for i, label in enumerate(labels)
    )


def epoch(value: str) -> float:
    return datetime.fromisoformat(value).replace(tzinfo=UTC).timestamp()


def cat_frame(unit: str, text: str, rc: int = 0) -> str:
    return f"{watch._CAT_BEGIN}{unit}\n{text.rstrip()}\n{watch._CAT_END}{rc}\n"


def resolve_frame(index: int, output: str, rc: int = 0) -> str:
    return f"{watch._RESOLVE_BEGIN}{index}\n{output.rstrip()}\n{watch._RESOLVE_END}{index}:{rc}\n"


def fake_single_timer_ssh(
    *,
    declaration: str,
    last_trigger: str,
    resolution: str = HOURLY_CALENDAR,
    resolution_rc: int = 0,
    active_state: str | None = None,
    active_enter: str | None = None,
):
    calendar_calls = 0

    def fake(host, command, timeout):
        nonlocal calendar_calls
        assert host == HOST
        if command == watch.LIST_COMMAND:
            return 0, LIST_ONE, ""
        if command == watch.build_cat_command(["billing.timer"]):
            return 0, cat_frame("billing.timer", declaration), ""
        if command == watch.build_show_command(["billing.timer"]):
            block = f"LastTriggerUSec={last_trigger}\nId=billing.timer\n"
            if active_state is not None:
                block += f"ActiveState={active_state}\n"
            if active_enter is not None:
                block += f"ActiveEnterTimestamp={active_enter}\n"
            return 0, block, ""
        if "systemd-analyze calendar" in command and "--base-time=@" in command:
            # Honour the base time like systemd does: the hourly elapses after it.
            base = int(command.split("--base-time=@", 1)[1].split()[0])
            return 0, resolve_frame(0, hourly_after(base)), ""
        if "systemd-analyze calendar" in command:
            if calendar_calls == 0:
                output = resolution
                rc = resolution_rc
            else:
                output = hourly_calendar(9 + 3 * calendar_calls)
                rc = 0
            calendar_calls += 1
            return 0, resolve_frame(0, output, rc), ""
        raise AssertionError(f"unexpected ssh command: {command}")

    return fake


def run_main(monkeypatch, tmp_path, *, extra=()) -> int:
    return watch.main(
        ["--host", HOST, "--dry-run", "--state-file", str(tmp_path / "state.json"), *extra]
    )


def test_parse_list_timers_takes_unit_from_variable_width_right_columns() -> None:
    fixture = LIST_ONE + "- - - - never-fired.timer never-fired.service\n"
    assert watch.parse_timer_list(fixture) == ["billing.timer", "never-fired.timer"]


def test_oncalendar_empty_assignment_resets_observed_daily_then_hourly_shape() -> None:
    declaration = """\
[Timer]
OnCalendar=daily

# /etc/systemd/system/report-build.timer.d/10-hourly.conf
[Timer]
OnCalendar=
OnCalendar=hourly
"""
    schedule = watch.parse_declared_schedule(declaration)
    assert schedule["OnCalendar"] == ["hourly"]
    assert "daily" not in schedule["OnCalendar"]


def test_empty_trigger_assignment_resets_monotonic_triggers_too() -> None:
    declaration = """\
[Timer]
OnUnitActiveSec=1min
OnCalendar=
OnCalendar=hourly
"""
    schedule = watch.parse_declared_schedule(declaration)
    assert schedule["OnUnitActiveSec"] == []
    assert schedule["OnCalendar"] == ["hourly"]


def test_trigger_reset_does_not_erase_declared_randomized_delay() -> None:
    declaration = """\
[Timer]
RandomizedDelaySec=15min
OnCalendar=daily
OnCalendar=
OnCalendar=hourly
"""
    schedule = watch.parse_declared_schedule(declaration)
    assert schedule["OnCalendar"] == ["hourly"]
    assert schedule["RandomizedDelaySec"] == ["15min"]


def test_first_sunday_calendar_uses_longest_consecutive_declared_gap() -> None:
    output = """\
    Next elapse: Sun 2027-10-03 04:30:00 UTC
   Iteration #2: Sun 2027-10-31 04:30:00 UTC
   Iteration #3: Sun 2027-12-05 04:30:00 UTC
"""
    assert watch.calendar_cadence(output) == 35 * 24 * 3600


def test_chained_three_iteration_batches_include_weekend_gap(monkeypatch) -> None:
    declaration = "[Timer]\nOnCalendar=Mon..Fri 09:30\n"
    batches = [
        """\
    Next elapse: Mon 2027-09-20 09:30:00 UTC
   Iteration #2: Tue 2027-09-21 09:30:00 UTC
   Iteration #3: Wed 2027-09-22 09:30:00 UTC
""",
        """\
    Next elapse: Thu 2027-09-23 09:30:00 UTC
   Iteration #2: Fri 2027-09-24 09:30:00 UTC
   Iteration #3: Mon 2027-09-27 09:30:00 UTC
""",
        """\
    Next elapse: Tue 2027-09-28 09:30:00 UTC
   Iteration #2: Wed 2027-09-29 09:30:00 UTC
   Iteration #3: Thu 2027-09-30 09:30:00 UTC
""",
        """\
    Next elapse: Fri 2027-10-01 09:30:00 UTC
   Iteration #2: Mon 2027-10-04 09:30:00 UTC
   Iteration #3: Tue 2027-10-05 09:30:00 UTC
""",
    ]
    calendar_calls = 0

    def fake(host, command, timeout):
        nonlocal calendar_calls
        if command == watch.LIST_COMMAND:
            return 0, LIST_ONE, ""
        if command == watch.build_cat_command(["billing.timer"]):
            return 0, cat_frame("billing.timer", declaration), ""
        if command == watch.build_show_command(["billing.timer"]):
            return 0, "LastTriggerUSec=Fri 2027-09-17 09:30:00 UTC\nId=billing.timer\n", ""
        if "systemd-analyze calendar" in command:
            output = batches[calendar_calls]
            calendar_calls += 1
            return 0, resolve_frame(0, output), ""
        raise AssertionError(command)

    monkeypatch.setattr(watch, "run_remote", fake)
    verdict, _, facts = watch.probe(HOST, 30, epoch("2027-09-19T13:31:00"), 2.0, 300.0)
    assert verdict == "ok"
    assert facts["timers"][0]["cadence_seconds"] == 3 * 24 * 3600
    assert calendar_calls == watch.CALENDAR_RESOLUTION_ROUNDS


def test_resolver_command_does_not_pipe_away_systemd_analyze_status() -> None:
    command = watch.build_resolve_command([("calendar", "hourly")])
    assert "systemd-analyze calendar --iterations=3" in command
    assert "hw_resolve_rc=$?" in command
    assert "|" not in command


def test_positive_control_ancient_last_trigger_is_findings_and_exit_1(
    monkeypatch, tmp_path, capsys
) -> None:
    """MUST-FIRE: an hourly billing timer silent for days is not healthy."""
    monkeypatch.setattr(
        watch,
        "run_remote",
        fake_single_timer_ssh(
            declaration="[Timer]\nOnCalendar=hourly\n",
            last_trigger="Tue 2027-08-31 00:00:00 UTC",
        ),
    )
    monkeypatch.setattr(watch.time, "time", lambda: epoch("2027-09-19T08:40:00"))

    assert run_main(monkeypatch, tmp_path) == watch.EXIT_FINDINGS
    output = capsys.readouterr().out
    assert "FINDINGS" in output
    assert "billing.timer" in output


def test_recent_trigger_is_ok_and_short_timer_floor_prevents_flap(monkeypatch) -> None:
    declaration = "[Timer]\nOnUnitActiveSec=1min\n"

    def fake(host, command, timeout):
        if command == watch.LIST_COMMAND:
            return 0, LIST_ONE, ""
        if command == watch.build_cat_command(["billing.timer"]):
            return 0, cat_frame("billing.timer", declaration), ""
        if command == watch.build_show_command(["billing.timer"]):
            return 0, "LastTriggerUSec=Sun 2027-09-19 08:36:01 UTC\nId=billing.timer\n", ""
        if command == watch.build_resolve_command([("timespan", "1min")]):
            return 0, resolve_frame(0, "Original: 1min\n      us: 60000000\n   Human: 1min"), ""
        raise AssertionError(command)

    monkeypatch.setattr(watch, "run_remote", fake)
    verdict, _, facts = watch.probe(HOST, 30, epoch("2027-09-19T08:40:00"), 2.0, 300.0)
    assert verdict == "ok"
    assert facts["timers"][0]["threshold_seconds"] == 300.0


def test_declared_randomized_delay_extends_threshold(monkeypatch) -> None:
    declaration = """\
[Timer]
OnUnitActiveSec=5min
RandomizedDelaySec=15min
"""

    def fake(host, command, timeout):
        if command == watch.LIST_COMMAND:
            return 0, LIST_ONE, ""
        if command == watch.build_cat_command(["billing.timer"]):
            return 0, cat_frame("billing.timer", declaration), ""
        if command == watch.build_show_command(["billing.timer"]):
            return 0, "LastTriggerUSec=Sun 2027-09-19 08:29:00 UTC\nId=billing.timer\n", ""
        expressions = [("timespan", "5min"), ("timespan", "15min")]
        if command == watch.build_resolve_command(expressions):
            output = resolve_frame(0, "us: 300000000")
            output += resolve_frame(1, "us: 900000000")
            return 0, output, ""
        raise AssertionError(command)

    monkeypatch.setattr(watch, "run_remote", fake)
    verdict, _, facts = watch.probe(HOST, 30, epoch("2027-09-19T08:40:00"), 2.0, 300.0)
    assert verdict == "ok"
    assert facts["timers"][0]["declared_slack_seconds"] == 900.0
    assert facts["timers"][0]["threshold_seconds"] == 1500.0


@pytest.mark.parametrize("resolver_rc", [0, 1])
def test_unparseable_calendar_is_unknown_even_if_a_pipeline_like_rc_is_zero(
    monkeypatch, tmp_path, resolver_rc
) -> None:
    failure = "Failed to parse calendar specification 'hourly': Invalid argument"
    monkeypatch.setattr(
        watch,
        "run_remote",
        fake_single_timer_ssh(
            declaration="[Timer]\nOnCalendar=hourly\n",
            last_trigger="Sun 2027-09-19 08:00:00 UTC",
            resolution=failure,
            resolution_rc=resolver_rc,
        ),
    )
    monkeypatch.setattr(watch.time, "time", lambda: epoch("2027-09-19T08:40:00"))
    assert run_main(monkeypatch, tmp_path) == watch.EXIT_UNKNOWN


def test_onboot_only_timer_is_unknown_not_ok(monkeypatch) -> None:
    declaration = "[Timer]\nOnBootSec=10min\n"

    def fake(host, command, timeout):
        if command == watch.LIST_COMMAND:
            return 0, LIST_ONE, ""
        if command == watch.build_cat_command(["billing.timer"]):
            return 0, cat_frame("billing.timer", declaration), ""
        if command == watch.build_show_command(["billing.timer"]):
            return 0, "LastTriggerUSec=Sun 2027-09-19 08:00:00 UTC\nId=billing.timer\n", ""
        raise AssertionError(command)

    monkeypatch.setattr(watch, "run_remote", fake)
    verdict, _, facts = watch.probe(HOST, 30, epoch("2027-09-19T08:40:00"), 2.0, 300.0)
    assert verdict == "unknown"
    assert "one-shot" in facts["unknowns"][0]["reason"]


def test_unit_vanishing_between_enumeration_and_show_is_unknown(monkeypatch) -> None:
    calendar_calls = 0

    def fake(host, command, timeout):
        nonlocal calendar_calls
        if command == watch.LIST_COMMAND:
            return 0, LIST_ONE, ""
        if command == watch.build_cat_command(["billing.timer"]):
            return 0, cat_frame("billing.timer", "[Timer]\nOnCalendar=hourly\n"), ""
        if command == watch.build_show_command(["billing.timer"]):
            return 0, "", ""
        if "systemd-analyze calendar" in command:
            output = hourly_calendar(9 + 3 * calendar_calls)
            calendar_calls += 1
            return 0, resolve_frame(0, output), ""
        raise AssertionError(command)

    monkeypatch.setattr(watch, "run_remote", fake)
    verdict, _, facts = watch.probe(HOST, 30, epoch("2027-09-19T08:40:00"), 2.0, 300.0)
    assert verdict == "unknown"
    assert "vanished" in facts["unknowns"][0]["reason"]


def test_ssh_failure_is_rc3_and_names_transport(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(
        watch,
        "run_remote",
        lambda *args: (
            255,
            "",
            "ssh: connect to host timers-host port 22: Operation timed out",
        ),
    )
    assert run_main(monkeypatch, tmp_path) == watch.EXIT_UNKNOWN
    output = capsys.readouterr().out
    assert "ssh" in output
    assert "Operation timed out" in output


def test_zero_timer_enumeration_is_unknown(monkeypatch) -> None:
    monkeypatch.setattr(watch, "run_remote", lambda *args: (0, "", ""))
    verdict, reason, _ = watch.probe(HOST, 30, 0.0, 2.0, 300.0)
    assert verdict == "unknown"
    assert "zero timers" in reason


def test_json_mode_is_plain_parseable_json(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(
        watch,
        "run_remote",
        fake_single_timer_ssh(
            declaration="[Timer]\nOnCalendar=hourly\n",
            last_trigger="Sun 2027-09-19 08:30:00 UTC",
        ),
    )
    monkeypatch.setattr(watch.time, "time", lambda: epoch("2027-09-19T08:40:00"))
    assert run_main(monkeypatch, tmp_path, extra=("--json",)) == watch.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "OK"
    assert payload["timers"][0]["unit"] == "billing.timer"


def test_dedupe_key_is_host_keyed() -> None:
    first = watch.dedupe_key_for("host-a", "overdue", "shared.timer")
    second = watch.dedupe_key_for("host-b", "overdue", "shared.timer")
    assert first != second
    assert "/host-a/" in first
    assert "/host-b/" in second


class _AlertResult:
    def __init__(self, success: bool):
        self.success = success


def test_failed_alert_delivery_does_not_latch(monkeypatch) -> None:
    sent = []
    monkeypatch.setattr(
        watch,
        "alert",
        lambda *args, **kwargs: (sent.append(kwargs["dedupe_key"]), _AlertResult(False))[1],
    )
    issue = {"kind": "unknown", "unit": "x.timer", "reason": "bad schedule"}
    alerted = watch.deliver_alerts(HOST, [issue], {}, 100.0, 3600.0)
    alerted = watch.deliver_alerts(HOST, [issue], alerted, 200.0, 3600.0)
    assert alerted == {}
    assert len(sent) == 2


def test_successful_alert_delivery_latches_until_reminder(monkeypatch) -> None:
    sent = []
    monkeypatch.setattr(
        watch,
        "alert",
        lambda *args, **kwargs: (sent.append(kwargs["dedupe_key"]), _AlertResult(True))[1],
    )
    issue = {
        "kind": "overdue",
        "unit": "x.timer",
        "age_seconds": 1000.0,
        "threshold_seconds": 300.0,
    }
    alerted = watch.deliver_alerts(HOST, [issue], {}, 100.0, 3600.0)
    watch.deliver_alerts(HOST, [issue], alerted, 200.0, 3600.0)
    assert sent == ["systemd-timer-liveness/overdue/timers-host/x.timer"]


def test_transport_unknown_preserves_existing_overdue_latch(monkeypatch, tmp_path) -> None:
    state_file = tmp_path / "state.json"
    overdue_key = watch.dedupe_key_for(HOST, "overdue", "billing.timer")
    state_file.write_text(json.dumps({"alerted": {overdue_key: 100.0}}))
    monkeypatch.setattr(
        watch,
        "probe",
        lambda *args: (
            "unknown",
            "enumerating timers on timers-host failed: connection refused",
            {"host": HOST, "stage": "list-timers", "findings": [], "unknowns": []},
        ),
    )
    monkeypatch.setattr(watch, "alert", lambda *args, **kwargs: _AlertResult(True))
    monkeypatch.setattr(watch.time, "time", lambda: 200.0)
    assert watch.main(["--host", HOST, "--state-file", str(state_file)]) == watch.EXIT_UNKNOWN
    state = json.loads(state_file.read_text())
    assert state["alerted"][overdue_key] == 100.0


# ---------------------------------------------------------------------------
# The three meanings of an empty LastTriggerUSec.
#
# Reporting every empty LastTriggerUSec as "cannot measure" makes a brand-new
# timer, or one that is merely inactive, look like an instrument failure. At a
# five-minute schedule that is a warning every five minutes forever, which gets
# muted -- and a muted detector is worse than the blind spot it closed.
#
# "I could not measure this" and "I measured it and it has not fired yet" are
# opposite facts.
# ---------------------------------------------------------------------------

HOURLY = "[Timer]\nOnCalendar=hourly\n"
FIXED_NOW = "2027-09-19T08:40:00"


def test_inactive_timer_is_its_own_bucket_not_cannot_measure(
    monkeypatch, tmp_path, capsys
) -> None:
    """A timer unit that is not active is a DEFINITE state, not a failed reading."""
    monkeypatch.setattr(
        watch,
        "run_remote",
        fake_single_timer_ssh(
            declaration=HOURLY, last_trigger="", active_state="inactive"
        ),
    )
    monkeypatch.setattr(watch.time, "time", lambda: epoch(FIXED_NOW))

    assert run_main(monkeypatch, tmp_path) == 0, "an inactive timer must not page"
    output = capsys.readouterr().out
    assert "UNKNOWN" not in output
    assert "inactive" in output, "and it must never be a silent zero"


def test_active_but_not_yet_due_is_ok_not_cannot_measure(
    monkeypatch, tmp_path, capsys
) -> None:
    """Installed twenty minutes ago; its first elapse is still ahead."""
    monkeypatch.setattr(
        watch,
        "run_remote",
        fake_single_timer_ssh(
            declaration=HOURLY,
            last_trigger="",
            active_state="active",
            active_enter="Sun 2027-09-19 08:20:00 UTC",
        ),
    )
    monkeypatch.setattr(watch.time, "time", lambda: epoch(FIXED_NOW))

    assert run_main(monkeypatch, tmp_path) == 0
    output = capsys.readouterr().out
    assert "UNKNOWN" not in output
    assert "FINDINGS" not in output


def test_positive_control_active_past_due_and_never_fired_is_a_finding(
    monkeypatch, tmp_path, capsys
) -> None:
    """MUST-FIRE: active, weeks past its hourly cadence, and it has never once fired.

    Collapsing every empty LastTrigger into "cannot measure" would exonerate this fault.
    """
    monkeypatch.setattr(
        watch,
        "run_remote",
        fake_single_timer_ssh(
            declaration=HOURLY,
            last_trigger="",
            active_state="active",
            active_enter="Tue 2027-08-31 00:00:00 UTC",
        ),
    )
    monkeypatch.setattr(watch.time, "time", lambda: epoch(FIXED_NOW))

    assert run_main(monkeypatch, tmp_path) == watch.EXIT_FINDINGS
    output = capsys.readouterr().out
    assert "FINDINGS" in output
    assert "billing.timer" in output


def test_absent_active_state_is_still_unknown(monkeypatch, tmp_path) -> None:
    """The three-way split NARROWS what counts as unmeasurable; it must not abolish it.

    If systemd reported no ActiveState at all, we genuinely cannot tell the
    three cases apart, and that is still UNKNOWN rather than OK.
    """
    monkeypatch.setattr(
        watch,
        "run_remote",
        fake_single_timer_ssh(declaration=HOURLY, last_trigger=""),
    )
    monkeypatch.setattr(watch.time, "time", lambda: epoch(FIXED_NOW))

    assert run_main(monkeypatch, tmp_path) == watch.EXIT_UNKNOWN


WINDOWED_LIST = """\
Thu 2027-09-23 12:00:00 UTC 13h Wed 2027-09-22 21:59:00 UTC 6min ago wake.timer wake.service
"""
MINUTE_WINDOW_CALENDAR = """\
    Next elapse: Thu 2027-09-23 12:00:00 UTC
   Iteration #2: Thu 2027-09-23 12:01:00 UTC
   Iteration #3: Thu 2027-09-23 12:02:00 UTC
"""


def fake_windowed_timer_ssh(last_trigger: str):
    """Every minute 12..21 UTC on weekdays: a business-hours timer."""
    declaration = "[Timer]\nOnCalendar=Mon..Fri *-*-* 12..21:*:00 UTC\n"

    def fake(host, command, timeout):
        if command == watch.LIST_COMMAND:
            return 0, WINDOWED_LIST, ""
        if command == watch.build_cat_command(["wake.timer"]):
            return 0, cat_frame("wake.timer", declaration), ""
        if command == watch.build_show_command(["wake.timer"]):
            return 0, f"LastTriggerUSec={last_trigger}\nId=wake.timer\n", ""
        if "systemd-analyze calendar" in command:
            if "--base-time=@" in command:
                base = int(command.split("--base-time=@", 1)[1].split()[0])
                if base >= epoch("2027-09-22T21:59:00"):
                    return 0, resolve_frame(0, MINUTE_WINDOW_CALENDAR), ""
                # an older trigger: the next minute inside the window
                nxt = datetime.fromtimestamp(base + 60, UTC)
                return 0, resolve_frame(0, f"    Next elapse: {nxt:%a %Y-%m-%d %H:%M:%S} UTC"), ""
            return 0, resolve_frame(0, MINUTE_WINDOW_CALENDAR), ""
        raise AssertionError(command)

    return fake


def test_windowed_timer_between_windows_is_not_overdue(monkeypatch) -> None:
    """A minute timer that stops at 21:59Z BY DECLARATION must not be overdue at 22:05Z."""
    monkeypatch.setattr(watch, "run_remote", fake_windowed_timer_ssh("Wed 2027-09-22 21:59:00 UTC"))
    verdict, _, facts = watch.probe(HOST, 30, epoch("2027-09-22T22:05:00"), 2.0, 300.0)
    assert verdict == "ok", facts["findings"]


def test_windowed_timer_that_stops_inside_its_window_is_still_overdue(monkeypatch) -> None:
    """MUST-FIRE: the same timer silent since 15:00Z on a weekday is a real outage."""
    monkeypatch.setattr(watch, "run_remote", fake_windowed_timer_ssh("Wed 2027-09-22 15:00:00 UTC"))
    verdict, _, facts = watch.probe(HOST, 30, epoch("2027-09-22T15:30:00"), 2.0, 300.0)
    assert verdict == "findings"
    assert facts["findings"][0]["unit"] == "wake.timer"


def test_a_never_fired_finding_can_be_alerted(monkeypatch) -> None:
    """A never-fired finding has no 'reason' field; alerting on it must not crash the run."""
    sent = []
    monkeypatch.setattr(
        watch, "alert",
        lambda *args, **kwargs: (sent.append(args[2]), _AlertResult(True))[1],
    )
    issue = {"kind": "never_fired", "unit": "x.timer", "age_seconds": 9000.0,
             "threshold_seconds": 7200.0}
    watch.deliver_alerts(HOST, [issue], {}, 100.0, 3600.0)
    assert sent and "never fired" in sent[0]


def test_without_a_host_commands_run_locally() -> None:
    rc, out, _err = watch.run_remote(None, "echo local-ok", 10)
    assert (rc, out.strip()) == (0, "local-ok")


def test_a_failing_local_transport_is_unknown(monkeypatch) -> None:
    monkeypatch.setattr(watch, "run_remote", lambda *args: (127, "", "systemctl: not found"))
    verdict, reason, facts = watch.probe(None, 30, 0.0, 2.0, 300.0)
    assert verdict == "unknown"
    assert "localhost" in reason and "not found" in reason


@pytest.mark.parametrize("content", ["{not json", "[]", '{"alerted": {"k": "yesterday"}}'])
def test_a_corrupt_state_file_is_unknown_and_left_untouched(monkeypatch, tmp_path, capsys, content) -> None:
    """MUST-FIRE: a healthy sweep over a broken latch record is exit 3, not a clean 0."""
    state_file = tmp_path / "state.json"
    state_file.write_text(content)
    monkeypatch.setattr(
        watch, "run_remote",
        fake_single_timer_ssh(declaration=HOURLY, last_trigger="Sun 2027-09-19 08:30:00 UTC"),
    )
    monkeypatch.setattr(watch.time, "time", lambda: epoch(FIXED_NOW))
    code = watch.main(["--host", HOST, "--state-file", str(state_file)])
    assert code == watch.EXIT_UNKNOWN
    assert state_file.read_text() == content
    assert "state file" in capsys.readouterr().out
