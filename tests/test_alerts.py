"""Tests for the alert library: receipts, dedupe, degraded fallback, sinks, and the live guard."""

from __future__ import annotations

import http.server
import json
import os
import signal
import socket
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from honest_watchdogs import alerts


class RecordingSink:
    """A sink whose outcome the test controls. ``live`` is configurable."""

    def __init__(self, name: str = "recorder", *, succeed: bool = True, live: bool = False,
                 reason: str = "boom") -> None:
        self.name = name
        self.live = live
        self.succeed = succeed
        self.reason = reason
        self.calls: list[alerts.Alert] = []

    def deliver(self, alert: alerts.Alert) -> alerts.DeliveryOutcome:
        self.calls.append(alert)
        if self.succeed:
            return alerts.DeliveryOutcome(success=True)
        return alerts.DeliveryOutcome(success=False, failure_reason=self.reason)


def _config(tmp_path: Path, *sinks, **kwargs) -> alerts.AlertConfig:
    return alerts.AlertConfig(
        sinks=tuple(sinks),
        receipt_dir=tmp_path / "receipts",
        fallback_receipt_dir=tmp_path / "fallback",
        **kwargs,
    )


def _receipts(path: Path) -> list[dict]:
    rows: list[dict] = []
    for file in sorted(path.glob("*-alerts.jsonl")):
        rows.extend(json.loads(line) for line in file.read_text().splitlines() if line.strip())
    return rows


# --------------------------------------------------------------------------- basics


def test_severity_is_validated() -> None:
    with pytest.raises(alerts.AlertConfigError):
        alerts.Alert(severity="loud", component="c", summary="s")
    assert alerts.Alert(severity=" WARN ", component="c", summary="s").severity == "warn"


def test_delivery_writes_one_receipt_per_sink_naming_the_outcome(tmp_path) -> None:
    ok, bad = RecordingSink("ok"), RecordingSink("bad", succeed=False, reason="HTTP 503")
    result = alerts.alert("critical", "unit", "disk full", config=_config(tmp_path, ok, bad))

    assert not result.success
    rows = _receipts(tmp_path / "receipts")
    assert {(r["sink"], r["status"]) for r in rows} == {("ok", "delivered"), ("bad", "failed")}
    failed = next(r for r in rows if r["sink"] == "bad")
    assert failed["failure_reason"] == "HTTP 503", "the receipt must say WHY it failed"


def test_a_sink_that_raises_is_a_failed_delivery_not_a_crash(tmp_path) -> None:
    class Exploding:
        name, live = "exploding", False

        def deliver(self, alert):
            raise RuntimeError("socket closed")

    result = alerts.alert("warn", "unit", "x", config=_config(tmp_path, Exploding()))
    assert not result.success
    assert "RuntimeError: socket closed" in result.deliveries[0].failure_reason


def test_stdout_sink_emits_one_json_line(tmp_path, capsys) -> None:
    alerts.alert("info", "unit", "hello", details={"a": 1},
                 config=_config(tmp_path, alerts.StdoutSink()))
    line = capsys.readouterr().out.strip()
    payload = json.loads(line)
    assert payload["summary"] == "hello"
    assert payload["details"] == {"a": 1}


def test_details_are_delivered_but_only_opted_in_scalars_are_persisted(tmp_path) -> None:
    sink = RecordingSink()
    alerts.alert(
        "warn", "unit", "s",
        details={"private_context": "delivered only"},
        receipt_details={"table": "events", "age_seconds": 12.5, "nested": {"x": 1},
                         "long": "y" * 1000},
        config=_config(tmp_path, sink),
    )
    assert sink.calls[0].details == {"private_context": "delivered only"}
    row = _receipts(tmp_path / "receipts")[0]
    assert "delivered only" not in json.dumps(row)
    assert row["details"]["table"] == "events"
    assert row["details"]["age_seconds"] == 12.5
    assert "nested" not in row["details"], "nested values are dropped, never stringified"
    assert len(row["details"]["long"]) == alerts.MAX_RECEIPT_DETAIL_STRING_LENGTH


def test_receipt_is_dated_by_attempt_time_not_alert_time(tmp_path) -> None:
    stale = datetime.now(UTC) - timedelta(days=30)
    result = alerts.alert("warn", "unit", "old", now=stale,
                          config=_config(tmp_path, RecordingSink()))
    assert result.receipt_path.name.startswith(datetime.now(UTC).strftime("%Y-%m-%d"))
    row = _receipts(tmp_path / "receipts")[0]
    assert row["alert_created_at"].startswith(stale.strftime("%Y-%m-%d"))


# --------------------------------------------------------------------------- dedupe


def test_successful_delivery_dedupes_within_window_and_expires(tmp_path) -> None:
    sink = RecordingSink()
    cfg = _config(tmp_path, sink, dedup_window_seconds=600)
    t0 = datetime(2030, 1, 1, tzinfo=UTC)

    first = alerts.alert("warn", "unit", "s", dedupe_key="k", now=t0, config=cfg)
    second = alerts.alert("warn", "unit", "s", dedupe_key="k", now=t0 + timedelta(seconds=60),
                          config=cfg)
    third = alerts.alert("warn", "unit", "s", dedupe_key="k", now=t0 + timedelta(seconds=601),
                         config=cfg)

    assert first.delivered and second.dedup_skipped and third.delivered
    assert len(sink.calls) == 2
    assert second.success, "a dedupe skip is a success for latching purposes"


def test_failed_delivery_does_not_latch_and_retries(tmp_path) -> None:
    """A page that did not land must not suppress the next attempt for the whole window."""
    sink = RecordingSink(succeed=False)
    cfg = _config(tmp_path, sink)
    alerts.alert("critical", "unit", "s", dedupe_key="k", config=cfg)
    alerts.alert("critical", "unit", "s", dedupe_key="k", config=cfg)
    assert len(sink.calls) == 2


def test_failed_delivery_retries_with_durable_state(tmp_path) -> None:
    sink = RecordingSink(succeed=False)
    cfg = _config(tmp_path, sink, dedup_state_path=tmp_path / "dedup.json")
    alerts.alert("critical", "unit", "s", dedupe_key="k", config=cfg)
    alerts.reset_dedup_state()
    alerts.alert("critical", "unit", "s", dedupe_key="k", config=cfg)
    assert len(sink.calls) == 2
    state = json.loads((tmp_path / "dedup.json").read_text())
    assert "k" not in state["entries"], "a released claim must not linger"


def test_partial_delivery_retries_every_sink(tmp_path) -> None:
    ok, bad = RecordingSink("ok"), RecordingSink("bad", succeed=False)
    cfg = _config(tmp_path, ok, bad)
    alerts.alert("critical", "unit", "s", dedupe_key="k", config=cfg)
    alerts.alert("critical", "unit", "s", dedupe_key="k", config=cfg)
    assert len(ok.calls) == 2 and len(bad.calls) == 2


def test_durable_dedupe_survives_a_process_restart(tmp_path) -> None:
    sink = RecordingSink()
    cfg = _config(tmp_path, sink, dedup_state_path=tmp_path / "dedup.json")
    alerts.alert("warn", "unit", "s", dedupe_key="k", config=cfg)
    alerts.reset_dedup_state()  # a new process has no in-memory cache
    second = alerts.alert("warn", "unit", "s", dedupe_key="k", config=cfg)
    assert second.dedup_skipped
    assert len(sink.calls) == 1


def test_an_abandoned_claim_is_reclaimed_after_its_ttl(tmp_path) -> None:
    """A sender that crashed mid-delivery must not suppress the key for the whole window."""
    state = tmp_path / "dedup.json"
    now = datetime.now(UTC)
    state.write_text(json.dumps({"version": 1, "entries": {"k": {
        "state": "claim", "timestamp": now.isoformat(),
        "acquired_at": time.time() - alerts.CLAIM_TTL_SECONDS - 5, "owner": "dead-sender"}}}))
    sink = RecordingSink()
    result = alerts.alert("warn", "unit", "s", dedupe_key="k",
                          config=_config(tmp_path, sink, dedup_state_path=state))
    assert result.delivered


def test_a_live_claim_blocks_a_concurrent_sender(tmp_path) -> None:
    state = tmp_path / "dedup.json"
    state.write_text(json.dumps({"version": 1, "entries": {"k": {
        "state": "claim", "timestamp": datetime.now(UTC).isoformat(),
        "acquired_at": time.time(), "owner": "other-sender"}}}))
    sink = RecordingSink()
    result = alerts.alert("warn", "unit", "s", dedupe_key="k",
                          config=_config(tmp_path, sink, dedup_state_path=state))
    assert result.dedup_skipped and not sink.calls


def test_a_stale_owner_cannot_overwrite_a_newer_claim(tmp_path) -> None:
    state = tmp_path / "dedup.json"
    now = datetime.now(UTC)
    assert alerts._dedup_claim("k", now, 600, "new-owner", state_path=state,
                               claim_ttl_seconds=30) is False
    alerts._dedup_confirm("k", now, 600, "old-owner", state_path=state, claim_ttl_seconds=30)
    alerts._dedup_release("k", now, 600, "old-owner", state_path=state, claim_ttl_seconds=30)
    entry = json.loads(state.read_text())["entries"]["k"]
    assert entry["state"] == "claim" and entry["owner"] == "new-owner"


def test_dry_run_neither_delivers_nor_latches(tmp_path) -> None:
    sink = RecordingSink()
    cfg = _config(tmp_path, sink)
    dry = alerts.alert("warn", "unit", "s", dedupe_key="k", config=cfg, dry_run=True)
    assert dry.success and not dry.delivered and not sink.calls
    real = alerts.alert("warn", "unit", "s", dedupe_key="k", config=cfg)
    assert real.delivered, "a dry run must not consume the dedupe window"


# --------------------------------------------------------------------------- the live guard


def test_a_test_suite_cannot_reach_a_live_sink(tmp_path, capsys) -> None:
    """MUST-FIRE: under pytest a live sink is suppressed, loudly, and the receipt says so."""
    live = RecordingSink("pager", live=True)
    local = RecordingSink("log", live=False)
    result = alerts.alert("page", "unit", "s", config=_config(tmp_path, live, local))

    assert not live.calls, "a live sink was called from a test"
    assert local.calls, "non-live sinks are unaffected"
    assert {d.sink: d.status for d in result.deliveries} == {"pager": "dry_run", "log": "delivered"}
    err = capsys.readouterr().err
    assert "SUPPRESSED live delivery" in err
    assert alerts.LIVE_DELIVERY_OPT_IN_ENV in err, "the message must say how to override"


def test_only_the_exact_opt_in_value_unlocks_live_delivery() -> None:
    base = {"PYTEST_CURRENT_TEST": "x"}
    for value in ("0", "", "true", "yes"):
        assert alerts.live_delivery_block_reason({**base, alerts.LIVE_DELIVERY_OPT_IN_ENV: value})
    assert alerts.live_delivery_block_reason({**base, alerts.LIVE_DELIVERY_OPT_IN_ENV: "1"}) is None
    assert alerts.live_delivery_block_reason({}) is None
    assert alerts.live_delivery_block_reason({alerts.LIVE_DELIVERY_SUPPRESS_ENV: "1"})


# --------------------------------------------------------------------------- webhook sink


class _Handler(http.server.BaseHTTPRequestHandler):
    status = 204
    delay = 0.0
    bodies: list[bytes] = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        type(self).bodies.append(self.rfile.read(length))
        time.sleep(type(self).delay)
        self.send_response(type(self).status)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def webhook_server():
    handler = type("H", (_Handler,), {"bodies": [], "status": 204, "delay": 0.0})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, handler
    server.shutdown()
    server.server_close()


def test_webhook_delivery_records_the_receivers_status(tmp_path, webhook_server, monkeypatch) -> None:
    monkeypatch.setenv(alerts.LIVE_DELIVERY_OPT_IN_ENV, "1")
    server, handler = webhook_server
    sink = alerts.WebhookSink(f"http://127.0.0.1:{server.server_port}/hook")
    result = alerts.alert("critical", "unit", "disk full", details={"host": "db1"},
                          dedupe_key="disk/db1", config=_config(tmp_path, sink))

    assert result.delivered and result.deliveries[0].http_status == 204
    body = json.loads(handler.bodies[0])
    assert body["summary"] == "disk full" and body["dedupe_key"] == "disk/db1"
    assert _receipts(tmp_path / "receipts")[0]["http_status"] == 204


def test_webhook_text_format(tmp_path, webhook_server, monkeypatch) -> None:
    monkeypatch.setenv(alerts.LIVE_DELIVERY_OPT_IN_ENV, "1")
    server, handler = webhook_server
    sink = alerts.WebhookSink(f"http://127.0.0.1:{server.server_port}/", payload_format="text")
    alerts.alert("warn", "unit", "hello", config=_config(tmp_path, sink))
    assert json.loads(handler.bodies[0]) == {"text": "WARN [unit] hello"}


def test_webhook_error_status_is_a_failure_with_its_code(tmp_path, webhook_server, monkeypatch) -> None:
    monkeypatch.setenv(alerts.LIVE_DELIVERY_OPT_IN_ENV, "1")
    server, handler = webhook_server
    handler.status = 500
    sink = alerts.WebhookSink(f"http://127.0.0.1:{server.server_port}/")
    result = alerts.alert("warn", "unit", "s", config=_config(tmp_path, sink))
    assert not result.success
    assert result.deliveries[0].http_status == 500
    assert "HTTP 500" in alerts.failure_detail(result)


def test_webhook_timeout_is_recorded_not_raised(tmp_path, webhook_server, monkeypatch) -> None:
    monkeypatch.setenv(alerts.LIVE_DELIVERY_OPT_IN_ENV, "1")
    server, handler = webhook_server
    handler.delay = 1.0
    sink = alerts.WebhookSink(f"http://127.0.0.1:{server.server_port}/", timeout_seconds=0.2)
    result = alerts.alert("warn", "unit", "s", config=_config(tmp_path, sink))
    assert not result.success
    assert result.deliveries[0].failure_reason == "request timed out"


def test_a_secret_in_the_webhook_url_never_reaches_receipts_or_output(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv(alerts.LIVE_DELIVERY_OPT_IN_ENV, "1")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]  # closed again: connection refused
    token = "tok-3f9a1c0e7b"
    sink = alerts.WebhookSink(f"http://127.0.0.1:{port}/hooks/{token}")
    result = alerts.alert("warn", "unit", "s", config=_config(tmp_path, sink))
    assert not result.success
    captured = capsys.readouterr()
    everything = captured.out + captured.err + json.dumps(_receipts(tmp_path / "receipts"))
    assert token not in everything
    assert "request failed" in result.deliveries[0].failure_reason


def test_webhook_url_must_be_http() -> None:
    with pytest.raises(alerts.AlertConfigError):
        alerts.WebhookSink("file:///etc/passwd")


# --------------------------------------------------------------------------- config


def test_config_defaults_to_stderr_without_a_url() -> None:
    cfg = alerts.load_alert_config({})
    assert [s.name for s in cfg.sinks] == ["stderr"]


def test_config_uses_webhook_when_a_url_is_set() -> None:
    cfg = alerts.load_alert_config({"WATCHDOG_WEBHOOK_URL": "https://hooks.example.com/x"})
    assert [(s.name, s.live) for s in cfg.sinks] == [("webhook", True)]


def test_config_rejects_a_webhook_sink_without_a_url_and_unknown_sinks() -> None:
    with pytest.raises(alerts.AlertConfigError, match="WATCHDOG_WEBHOOK_URL"):
        alerts.load_alert_config({"WATCHDOG_ALERT_SINKS": "webhook"})
    with pytest.raises(alerts.AlertConfigError, match="unknown sink"):
        alerts.load_alert_config({"WATCHDOG_ALERT_SINKS": "carrier-pigeon"})


def test_failure_detail_names_the_cause_or_says_there_was_none() -> None:
    from types import SimpleNamespace as NS

    with_reason = NS(deliveries=(NS(sink="webhook", success=False,
                                    failure_reason="request failed: SSLCertVerificationError",
                                    http_status=None),))
    assert "SSLCertVerificationError" in alerts.failure_detail(with_reason)
    without = NS(deliveries=(NS(sink="webhook", success=False, failure_reason="", http_status=None),))
    assert "no per-sink reason" in alerts.failure_detail(without)


def test_cli_is_a_positive_control_for_the_alert_path(monkeypatch, capsys) -> None:
    monkeypatch.setenv("WATCHDOG_ALERT_SINKS", "stdout")
    assert alerts.main(["--severity", "warn", "path check"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["summary"] == "path check"
    assert json.loads(captured.err.strip().splitlines()[-1])["deliveries"][0]["status"] == "delivered"


def test_cli_reports_misconfiguration_as_2(monkeypatch) -> None:
    monkeypatch.setenv("WATCHDOG_ALERT_SINKS", "webhook")
    assert alerts.main(["x"]) == 2


# --------------------------------------------------------------------------- receipt deadline
#
# A receipt path on a wedged network mount does not raise, it BLOCKS. The central test opens a
# real FIFO rather than mocking os.open: a FIFO opened for writing blocks until a reader arrives,
# which reproduces the actual syscall behaviour. A stub that cannot block is a blind spot shaped
# exactly like the bug.


def test_a_healthy_receipt_path_is_written_and_not_degraded(tmp_path) -> None:
    target = tmp_path / "receipts" / "2030-01-01-alerts.jsonl"
    fallback = tmp_path / "fallback"
    landed = alerts.append_receipt(target, {"probe": "ok"}, timeout=5.0, fallback_dir=fallback)
    assert landed == target
    assert json.loads(target.read_text()) == {"probe": "ok"}
    assert not fallback.exists()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX only")
def test_a_genuinely_blocking_open_degrades_instead_of_hanging(tmp_path) -> None:
    target = tmp_path / "2030-01-01-alerts.jsonl"
    os.mkfifo(target)
    fallback = tmp_path / "fallback"

    started = time.monotonic()
    landed = alerts.append_receipt(target, {"probe": "wedged", "severity": "critical"},
                                   timeout=0.5, fallback_dir=fallback)
    assert time.monotonic() - started < 5.0, "the write hung instead of degrading"

    rows = [json.loads(line) for line in landed.read_text().splitlines()]
    assert len(rows) == 1, "THE RECEIPT WAS DROPPED -- worse than the hang it replaces"
    row = rows[0]
    assert row["severity"] == "critical", "the original content must survive the degrade"
    assert row["receipt_degraded"] is True
    assert row["receipt_intended_path"] == str(target)
    assert "ReceiptWriteTimeout" in row["receipt_degrade_reason"]


def test_an_oserror_also_degrades_and_keeps_the_receipt(tmp_path) -> None:
    blocker = tmp_path / "blocked"
    blocker.write_text("a file, so it cannot be a parent directory")
    landed = alerts.append_receipt(blocker / "x-alerts.jsonl", {"probe": "oserror"},
                                   timeout=5.0, fallback_dir=tmp_path / "fallback")
    row = json.loads(landed.read_text())
    assert row["probe"] == "oserror" and row["receipt_degraded"] is True


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX only")
def test_the_deadline_is_cancelled_so_no_stray_alarm_fires_later(tmp_path) -> None:
    target = tmp_path / "x-alerts.jsonl"
    os.mkfifo(target)
    alerts.append_receipt(target, {"probe": "x"}, timeout=0.3, fallback_dir=tmp_path / "fb")
    remaining, _ = signal.setitimer(signal.ITIMER_REAL, 0)
    assert remaining == 0.0, "an ITIMER was left armed after the write returned"


def test_off_the_main_thread_a_healthy_write_still_succeeds(tmp_path) -> None:
    """SIGALRM only works on the main thread; off it the write is unbounded, not broken."""
    target = tmp_path / "receipts" / "x-alerts.jsonl"
    outcome: list[str] = []

    def worker() -> None:
        try:
            alerts.append_receipt(target, {"probe": "thread"}, timeout=0.5,
                                  fallback_dir=tmp_path / "fb")
            outcome.append("wrote")
        except Exception as exc:  # noqa: BLE001
            outcome.append(type(exc).__name__)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=10)
    assert outcome == ["wrote"]


def test_send_alert_degrades_receipts_through_the_real_path(tmp_path, capsys) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    cfg = alerts.AlertConfig(sinks=(RecordingSink(),), receipt_dir=blocker,
                             fallback_receipt_dir=tmp_path / "fallback")
    result = alerts.alert("warn", "unit", "s", config=cfg)
    assert result.delivered
    rows = _receipts(tmp_path / "fallback")
    assert rows and rows[0]["receipt_degraded"] is True
    assert "ALERT RECEIPT DEGRADED" in capsys.readouterr().err


def test_a_corrupt_dedupe_state_file_is_preserved_and_does_not_suppress(tmp_path, capsys) -> None:
    """Fail toward sending, loudly, and keep the evidence."""
    state = tmp_path / "dedup.json"
    state.write_text("{truncated")
    sink = RecordingSink()
    result = alerts.alert("critical", "unit", "s", dedupe_key="k",
                          config=_config(tmp_path, sink, dedup_state_path=state))
    assert result.delivered and len(sink.calls) == 1
    assert (tmp_path / "dedup.json.corrupt").read_text() == "{truncated"
    assert "was unreadable" in capsys.readouterr().err


def test_cli_json_puts_the_report_on_stdout(monkeypatch, capsys) -> None:
    monkeypatch.setenv("WATCHDOG_ALERT_SINKS", "stderr")
    assert alerts.main(["--json", "x"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["deliveries"][0]["status"] == "delivered"
