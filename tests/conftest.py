"""Every test runs with alerts pointed at a temp directory and no webhook configured.

The alerts library also refuses live delivery under pytest on its own; this fixture is the
second layer, so a test that forgets both still cannot write outside its tmp_path.
"""

from __future__ import annotations

import pytest

from honest_watchdogs import alerts


@pytest.fixture(autouse=True)
def _hermetic_alerts(tmp_path, monkeypatch):
    for key in ("WATCHDOG_WEBHOOK_URL", "WATCHDOG_DEDUP_STATE", "WATCHDOG_LABEL_PREFIX",
                "WATCHDOG_MIRROR_DESTINATION", "WATCHDOG_MOUNT_POINT",
                "WATCHDOG_NONZERO_FINDINGS_LABELS", alerts.LIVE_DELIVERY_OPT_IN_ENV,
                alerts.LIVE_DELIVERY_SUPPRESS_ENV):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("WATCHDOG_ALERT_SINKS", "stderr")
    monkeypatch.setenv("WATCHDOG_RECEIPT_DIR", str(tmp_path / "_receipts"))
    monkeypatch.setenv("WATCHDOG_FALLBACK_RECEIPT_DIR", str(tmp_path / "_receipts_degraded"))
    alerts.reset_dedup_state()
    yield
    alerts.reset_dedup_state()
