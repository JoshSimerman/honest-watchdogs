"""Alert delivery with receipts, dedupe, and a degraded fallback.

The rules this module exists to enforce:

* **"Sent" is not "delivered".** Every delivery attempt, successful or not, appends one JSON line
  to a dated receipt file. A receipt records what the receiver said (HTTP status, failure reason),
  not what the sender hoped.
* **A receipt is never dropped.** A receipt directory on a wedged network mount does not raise,
  it blocks. The write is bounded by a deadline, and on timeout or error the receipt goes to a
  local fallback directory, marked ``receipt_degraded``. The deadline chooses a different
  destination; it never chooses not to record.
* **Dedupe latches only on successful delivery.** A dedupe key is *claimed* before delivery,
  *confirmed* only if every sink delivered, and *released* otherwise, so a failed page stays
  retryable instead of being silenced for the whole dedupe window.
* **A test suite cannot reach a human.** Under pytest, live sinks degrade to dry-run and say so
  loudly on stderr, unless ``HONEST_WATCHDOGS_ALLOW_LIVE=1`` is set on purpose.

Sinks are pluggable. Two ship here: :class:`StdoutSink` / :class:`StderrSink` (one JSON line per
alert) and :class:`WebhookSink` (a generic JSON POST). Anything with a ``name``, a ``live`` flag
and a ``deliver(alert)`` method is a sink.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol, TextIO

from .exitcodes import EXIT_FINDINGS, EXIT_MISCONFIGURED, EXIT_OK

Severity = Literal["info", "warn", "critical", "page"]
SEVERITIES: tuple[str, ...] = ("info", "warn", "critical", "page")

DEFAULT_STATE_ROOT = Path("~/.local/state/honest-watchdogs")
DEFAULT_RECEIPT_DIR = DEFAULT_STATE_ROOT / "receipts"
# Where a degraded receipt goes. It should be local disk: the point is to leave the failure
# domain that just refused the write.
DEFAULT_FALLBACK_RECEIPT_DIR = Path("~/.cache/honest-watchdogs/receipts-degraded")
DEFAULT_DEDUP_WINDOW_SECONDS = 600
DEFAULT_HTTP_TIMEOUT_SECONDS = 5.0
# A receipt write that cannot finish in this long is a wedged mount, not a slow one.
RECEIPT_WRITE_TIMEOUT_SECONDS = 5.0
MAX_DEDUP_ENTRIES = 1000
MAX_RECEIPT_DETAIL_STRING_LENGTH = 256
# A claim older than this is presumed abandoned by a crashed sender. It must exceed a realistic
# delivery time and stay far below the dedupe window, so a crash cannot suppress for long.
CLAIM_TTL_SECONDS = 30.0

LIVE_DELIVERY_OPT_IN_ENV = "HONEST_WATCHDOGS_ALLOW_LIVE"
LIVE_DELIVERY_SUPPRESS_ENV = "HONEST_WATCHDOGS_SUPPRESS_LIVE"

RECEIPT_SOURCE = "honest-watchdogs"


class AlertConfigError(ValueError):
    """Alerts cannot be configured safely."""


# --------------------------------------------------------------------------- data model


@dataclass(frozen=True)
class Alert:
    """One logical alert, before it is fanned out to sinks."""

    severity: str
    component: str
    summary: str
    details: Mapping[str, object] | str | None = None
    dedupe_key: str | None = None
    tags: Iterable[str] = ()
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    # Durable context is opt-in: ``details`` is delivered but never persisted in receipts;
    # ``receipt_details`` is persisted after being reduced to bounded scalars.
    receipt_details: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        severity = _single_line(self.severity).lower()
        if severity not in SEVERITIES:
            raise AlertConfigError(
                f"invalid severity {self.severity!r}; allowed: {', '.join(SEVERITIES)}"
            )
        component = _single_line(self.component)
        summary = _single_line(self.summary)
        if not component:
            raise AlertConfigError("component must not be empty")
        if not summary:
            raise AlertConfigError("summary must not be empty")
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "component", component)
        object.__setattr__(self, "summary", summary)
        object.__setattr__(self, "tags", _normalize_tags(self.tags))
        object.__setattr__(self, "created_at", _as_utc(self.created_at))

    def to_json(self) -> dict[str, object]:
        return {
            "severity": self.severity,
            "component": self.component,
            "summary": self.summary,
            "details": self.details,
            "dedupe_key": dedupe_key_for(self),
            "tags": list(self.tags),
            "created_at": _iso(self.created_at),
        }


@dataclass(frozen=True, kw_only=True)
class DeliveryOutcome:
    """What one sink reported for one attempt."""

    success: bool
    http_status: int | None = None
    failure_reason: str = ""


class Sink(Protocol):
    """Anything that can deliver an alert.

    ``live`` means the sink reaches something outside this process (a person, a chat room, a
    pager). Live sinks are the ones suppressed under pytest.
    """

    name: str
    live: bool

    def deliver(self, alert: Alert) -> DeliveryOutcome: ...


@dataclass(frozen=True, kw_only=True)
class SinkDelivery:
    """One sink's result for one logical alert."""

    sink: str
    success: bool
    dedup_skipped: bool = False
    dry_run: bool = False
    http_status: int | None = None
    failure_reason: str = ""

    @property
    def status(self) -> str:
        if self.dedup_skipped:
            return "dedup_skipped"
        if self.dry_run:
            return "dry_run"
        return "delivered" if self.success else "failed"


@dataclass(frozen=True, kw_only=True)
class AlertResult:
    severity: str
    component: str
    summary: str
    dedupe_key: str
    deliveries: tuple[SinkDelivery, ...]
    receipt_path: Path

    @property
    def success(self) -> bool:
        """Every sink delivered, dry-ran, or was inside the dedupe window.

        This is what a caller should latch on. A failed delivery leaves it False, so the caller
        keeps the condition retryable.
        """

        return bool(self.deliveries) and all(
            d.success or d.dedup_skipped for d in self.deliveries
        )

    @property
    def delivered(self) -> bool:
        """Every sink got a real, acknowledged delivery (no dry-run, no dedupe skip)."""

        return bool(self.deliveries) and all(
            d.success and not d.dry_run and not d.dedup_skipped for d in self.deliveries
        )

    @property
    def dedup_skipped(self) -> bool:
        return bool(self.deliveries) and all(d.dedup_skipped for d in self.deliveries)


# --------------------------------------------------------------------------- sinks


class StreamSink:
    """Writes one JSON line per alert to a text stream. Not live."""

    name = "stream"
    live = False

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream

    def _target(self) -> TextIO:
        return self._stream if self._stream is not None else sys.stdout

    def deliver(self, alert: Alert) -> DeliveryOutcome:
        try:
            target = self._target()
            target.write(json.dumps(alert.to_json(), sort_keys=True, default=str) + "\n")
            target.flush()
        except (OSError, ValueError) as exc:
            return DeliveryOutcome(success=False, failure_reason=f"{type(exc).__name__}: {exc}")
        return DeliveryOutcome(success=True)


class StdoutSink(StreamSink):
    name = "stdout"

    def _target(self) -> TextIO:
        return self._stream if self._stream is not None else sys.stdout


class StderrSink(StreamSink):
    name = "stderr"

    def _target(self) -> TextIO:
        return self._stream if self._stream is not None else sys.stderr


Opener = Callable[..., object]


class WebhookSink:
    """POSTs the alert as JSON to a URL. Live.

    ``payload_format="json"`` sends the alert's own fields. ``payload_format="text"`` sends
    ``{"text": "<SEVERITY> [component] summary"}``, a shape many chat webhooks accept.

    Success means the receiver answered 2xx. Anything else, including a timeout, is a failure
    with its reason recorded; the reason is the only artifact a failed delivery produces, so it
    is never discarded.
    """

    live = True

    def __init__(
        self,
        url: str,
        *,
        name: str = "webhook",
        timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
        payload_format: str = "json",
        headers: Mapping[str, str] | None = None,
        opener: Opener | None = None,
    ) -> None:
        url = _single_line(url)
        if not url:
            raise AlertConfigError("webhook sink requires a URL")
        if not url.startswith(("https://", "http://")):
            raise AlertConfigError("webhook URL must be http(s)")
        if payload_format not in ("json", "text"):
            raise AlertConfigError("payload_format must be 'json' or 'text'")
        if timeout_seconds <= 0:
            raise AlertConfigError("webhook timeout must be positive")
        self.name = name
        self._url = url
        self._timeout = timeout_seconds
        self._format = payload_format
        self._headers = dict(headers or {})
        self._opener = opener or urllib.request.urlopen

    def payload(self, alert: Alert) -> dict[str, object]:
        if self._format == "text":
            return {
                "text": f"{alert.severity.upper()} [{alert.component}] {alert.summary}"
                + (f"\n{_details_text(alert.details)}" if alert.details else "")
            }
        return alert.to_json()

    def deliver(self, alert: Alert) -> DeliveryOutcome:
        body = json.dumps(self.payload(alert), default=str, separators=(",", ":")).encode()
        request = urllib.request.Request(
            self._url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "honest-watchdogs/1",
                **self._headers,
            },
        )
        try:
            response = self._opener(request, timeout=self._timeout)
            try:
                read = getattr(response, "read", None)
                if callable(read):
                    read()
                status = _response_status(response)
            finally:
                close = getattr(response, "close", None)
                if callable(close):
                    close()
        except urllib.error.HTTPError as exc:
            return DeliveryOutcome(
                success=False, http_status=int(exc.code), failure_reason=f"HTTP {exc.code}"
            )
        except TimeoutError:
            return DeliveryOutcome(success=False, failure_reason="request timed out")
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                return DeliveryOutcome(success=False, failure_reason="request timed out")
            return DeliveryOutcome(
                success=False, failure_reason=f"request failed: {_reason_text(exc.reason)}"
            )
        except OSError as exc:
            return DeliveryOutcome(
                success=False, failure_reason=f"request failed: {_reason_text(exc)}"
            )
        return DeliveryOutcome(success=200 <= status < 300, http_status=status,
                               failure_reason="" if 200 <= status < 300 else f"HTTP {status}")


# --------------------------------------------------------------------------- config


@dataclass(frozen=True)
class AlertConfig:
    sinks: tuple[Sink, ...]
    receipt_dir: Path = DEFAULT_RECEIPT_DIR
    fallback_receipt_dir: Path = DEFAULT_FALLBACK_RECEIPT_DIR
    dedup_window_seconds: int = DEFAULT_DEDUP_WINDOW_SECONDS
    dedup_state_path: Path | None = None
    receipt_timeout_seconds: float = RECEIPT_WRITE_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if not self.sinks:
            raise AlertConfigError("at least one sink is required")
        names = [sink.name for sink in self.sinks]
        if len(set(names)) != len(names):
            raise AlertConfigError(f"sink names must be unique: {names}")
        if self.dedup_window_seconds < 0:
            raise AlertConfigError("dedup_window_seconds must not be negative")
        object.__setattr__(self, "receipt_dir", Path(self.receipt_dir).expanduser())
        object.__setattr__(
            self, "fallback_receipt_dir", Path(self.fallback_receipt_dir).expanduser()
        )
        if self.dedup_state_path is not None:
            object.__setattr__(self, "dedup_state_path", Path(self.dedup_state_path).expanduser())


def load_alert_config(env: Mapping[str, str] | None = None) -> AlertConfig:
    """Build a config from environment variables.

    ``WATCHDOG_ALERT_SINKS``      comma list of ``stdout``, ``stderr``, ``webhook``.
                                  Default: ``webhook`` if a URL is set, otherwise ``stderr``.
    ``WATCHDOG_WEBHOOK_URL``      target of the webhook sink.
    ``WATCHDOG_WEBHOOK_FORMAT``   ``json`` (default) or ``text``.
    ``WATCHDOG_WEBHOOK_TIMEOUT``  seconds, default 5.
    ``WATCHDOG_RECEIPT_DIR``      receipt JSONL directory.
    ``WATCHDOG_FALLBACK_RECEIPT_DIR``  where receipts go when the receipt dir is unwritable.
    ``WATCHDOG_DEDUP_WINDOW_SECONDS``  default 600; 0 disables dedupe.
    ``WATCHDOG_DEDUP_STATE``      file for cross-process dedupe state (default: in-process only).
    """

    source = dict(os.environ if env is None else env)
    url = _single_line(source.get("WATCHDOG_WEBHOOK_URL", ""))
    requested = _single_line(source.get("WATCHDOG_ALERT_SINKS", ""))
    names = [n.strip().lower() for n in requested.split(",") if n.strip()] or (
        ["webhook"] if url else ["stderr"]
    )
    sinks: list[Sink] = []
    for name in names:
        if name == "stdout":
            sinks.append(StdoutSink())
        elif name == "stderr":
            sinks.append(StderrSink())
        elif name == "webhook":
            if not url:
                raise AlertConfigError("sink 'webhook' requested but WATCHDOG_WEBHOOK_URL is unset")
            sinks.append(
                WebhookSink(
                    url,
                    payload_format=source.get("WATCHDOG_WEBHOOK_FORMAT", "json") or "json",
                    timeout_seconds=_float(source, "WATCHDOG_WEBHOOK_TIMEOUT",
                                           DEFAULT_HTTP_TIMEOUT_SECONDS),
                )
            )
        else:
            raise AlertConfigError(f"unknown sink {name!r}; expected stdout, stderr or webhook")
    dedup_state = _single_line(source.get("WATCHDOG_DEDUP_STATE", ""))
    return AlertConfig(
        sinks=tuple(sinks),
        receipt_dir=Path(source.get("WATCHDOG_RECEIPT_DIR") or DEFAULT_RECEIPT_DIR),
        fallback_receipt_dir=Path(
            source.get("WATCHDOG_FALLBACK_RECEIPT_DIR") or DEFAULT_FALLBACK_RECEIPT_DIR
        ),
        dedup_window_seconds=int(
            _float(source, "WATCHDOG_DEDUP_WINDOW_SECONDS", DEFAULT_DEDUP_WINDOW_SECONDS)
        ),
        dedup_state_path=Path(dedup_state) if dedup_state else None,
    )


# --------------------------------------------------------------------------- live guard


def live_delivery_block_reason(env: Mapping[str, str] | None = None) -> str | None:
    """Why live sinks must be suppressed for this process, or None to allow them.

    A test that calls the real sender pages a real person, and no amount of care by whoever
    wrote the test prevents that. So the guard lives in the one function every alert passes
    through. It fails toward NOT sending, and says so loudly: a silent suppression would create
    the opposite defect, a detector that believes it paged and did not.

    The opt-in exists on purpose. Proving a new detector can fire against a live channel is a
    legitimate thing to do; without a way to say "yes, really", the next person proving one
    deletes the guard.
    """

    source = os.environ if env is None else env
    if source.get(LIVE_DELIVERY_OPT_IN_ENV) == "1":
        return None
    if source.get(LIVE_DELIVERY_SUPPRESS_ENV) == "1":
        return f"{LIVE_DELIVERY_SUPPRESS_ENV}=1 is set"
    if source.get("PYTEST_CURRENT_TEST"):
        return "running under pytest"
    return None


# --------------------------------------------------------------------------- sending


def alert(
    severity: str,
    component: str,
    summary: str,
    details: Mapping[str, object] | str | None = None,
    dedupe_key: str | None = None,
    tags: Iterable[str] = (),
    *,
    receipt_details: Mapping[str, object] | None = None,
    config: AlertConfig | None = None,
    dry_run: bool = False,
    now: datetime | None = None,
) -> AlertResult:
    """Build an :class:`Alert` and send it. See :func:`send_alert`."""

    item = Alert(
        severity=severity,
        component=component,
        summary=summary,
        details=details,
        dedupe_key=dedupe_key,
        tags=tags,
        created_at=_as_utc(now or datetime.now(UTC)),
        receipt_details=receipt_details,
    )
    return send_alert(item, config=config, dry_run=dry_run)


def send_alert(
    item: Alert,
    *,
    config: AlertConfig | None = None,
    dry_run: bool = False,
) -> AlertResult:
    """Deliver ``item`` to every sink, writing one receipt line per sink."""

    cfg = config or load_alert_config()
    live_blocked = None
    if not dry_run and any(sink.live for sink in cfg.sinks):
        live_blocked = live_delivery_block_reason()
        if live_blocked is not None:
            print(
                f"honest-watchdogs alerts: SUPPRESSED live delivery of "
                f"{item.component}/{item.severity} -- {live_blocked}. "
                f"Set {LIVE_DELIVERY_OPT_IN_ENV}=1 to deliver deliberately.",
                file=sys.stderr,
            )

    key = dedupe_key_for(item)
    # A receipt is delivery evidence, so the ATTEMPT time owns its timestamp and dated path,
    # not the alert's creation time (which a caller may have supplied, or corrupted).
    attempted_at = datetime.now(UTC)
    receipt_path = cfg.receipt_dir / f"{attempted_at:%Y-%m-%d}-alerts.jsonl"
    ttl = CLAIM_TTL_SECONDS

    claim_token: str | None = None
    dedup_skipped = False
    if not dry_run and cfg.dedup_window_seconds > 0:
        claim_token = uuid.uuid4().hex
        dedup_skipped = _dedup_claim(
            key, item.created_at, cfg.dedup_window_seconds, claim_token,
            state_path=cfg.dedup_state_path, claim_ttl_seconds=ttl,
        )
        if dedup_skipped:
            claim_token = None

    deliveries: list[SinkDelivery] = []
    fully_delivered = False
    try:
        for sink in cfg.sinks:
            if dedup_skipped:
                delivery = SinkDelivery(sink=sink.name, success=True, dedup_skipped=True)
            elif dry_run or (sink.live and live_blocked is not None):
                delivery = SinkDelivery(sink=sink.name, success=True, dry_run=True)
            else:
                try:
                    outcome = sink.deliver(item)
                except Exception as exc:  # a sink that raises is a failed delivery, not a crash
                    outcome = DeliveryOutcome(
                        success=False, failure_reason=f"{type(exc).__name__}: {exc}"
                    )
                delivery = SinkDelivery(
                    sink=sink.name,
                    success=outcome.success,
                    http_status=outcome.http_status,
                    failure_reason=outcome.failure_reason,
                )
            append_receipt(
                receipt_path,
                _receipt_event(item, key, delivery, attempted_at, live=sink.live),
                timeout=cfg.receipt_timeout_seconds,
                fallback_dir=cfg.fallback_receipt_dir,
            )
            deliveries.append(delivery)
        fully_delivered = bool(deliveries) and all(
            d.success and not d.dry_run for d in deliveries
        )
    finally:
        if claim_token is not None:
            if fully_delivered:
                _dedup_confirm(key, item.created_at, cfg.dedup_window_seconds, claim_token,
                               state_path=cfg.dedup_state_path, claim_ttl_seconds=ttl)
            else:
                _dedup_release(key, item.created_at, cfg.dedup_window_seconds, claim_token,
                               state_path=cfg.dedup_state_path, claim_ttl_seconds=ttl)

    return AlertResult(
        severity=item.severity,
        component=item.component,
        summary=item.summary,
        dedupe_key=key,
        deliveries=tuple(deliveries),
        receipt_path=receipt_path,
    )


def dedupe_key_for(item: Alert) -> str:
    supplied = _single_line(item.dedupe_key or "")
    if supplied:
        return supplied
    raw = "\n".join((item.severity, item.component, item.summary))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def failure_detail(result: object) -> str:
    """Name every failed sink's reason, or say explicitly that none was given.

    A delivery failure produces no exception and no other log. An error message that says only
    "delivery failed" discards the cause in exactly the record written to diagnose it.
    """

    parts: list[str] = []
    for d in getattr(result, "deliveries", ()) or ():
        if getattr(d, "success", False):
            continue
        reason = getattr(d, "failure_reason", "") or ""
        status = getattr(d, "http_status", None)
        bits = [b for b in (reason, f"HTTP {status}" if status is not None and
                            f"HTTP {status}" != reason else "") if b]
        if bits:
            parts.append(f"{getattr(d, 'sink', '?')}: {' '.join(bits)}")
    return "; ".join(parts) if parts else "(sender reported no per-sink reason)"


# --------------------------------------------------------------------------- receipts


class ReceiptWriteTimeout(Exception):
    """The receipt write did not complete inside its deadline."""


@contextlib.contextmanager
def _deadline(seconds: float) -> Iterator[None]:
    """Bound a blocking syscall with SIGALRM, or do nothing if that is impossible.

    A blocked ``open()`` on a wedged network mount does not raise; it blocks, and
    ``except OSError`` cannot catch a hang. SIGALRM keeps the alert path cheap, at the cost of
    working only on the main thread. Off the main thread the write runs unbounded, and the
    docs say so: pretending to bound something is worse than not bounding it.
    """

    if seconds <= 0 or threading.current_thread() is not threading.main_thread():
        yield
        return

    def _fire(_signum: int, _frame: object) -> None:
        raise ReceiptWriteTimeout(f"receipt write exceeded {seconds}s")

    previous = signal.signal(signal.SIGALRM, _fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _write_line(path: Path, line: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)


def append_receipt(
    path: Path,
    event: Mapping[str, object],
    *,
    timeout: float = RECEIPT_WRITE_TIMEOUT_SECONDS,
    fallback_dir: Path = DEFAULT_FALLBACK_RECEIPT_DIR,
) -> Path:
    """Append one receipt line; degrade to ``fallback_dir`` rather than hang or drop.

    The fallback trigger is a real bounded WRITE, never an existence check: on some systems a
    permission layer allows metadata while denying content, so ``path.exists()`` returns True
    under exactly the failure the fallback exists for. Only attempting the write can tell you.

    Returns the path the receipt actually landed in.
    """

    line = json.dumps(event, sort_keys=True, separators=(",", ":"), default=str).encode() + b"\n"
    try:
        with _deadline(timeout):
            _write_line(path, line)
        return path
    except (ReceiptWriteTimeout, OSError) as exc:
        degraded = dict(event)
        degraded["receipt_degraded"] = True
        degraded["receipt_intended_path"] = str(path)
        degraded["receipt_degrade_reason"] = f"{type(exc).__name__}: {exc}"
        fallback_path = Path(fallback_dir).expanduser() / path.name
        # Loud as well: a receipt written somewhere nobody looks is the same defect as a
        # detector nobody reads.
        print(
            f"ALERT RECEIPT DEGRADED: {path} unwritable ({type(exc).__name__}); "
            f"wrote {fallback_path} instead",
            file=sys.stderr,
        )
        _write_line(
            fallback_path,
            json.dumps(degraded, sort_keys=True, separators=(",", ":"), default=str).encode()
            + b"\n",
        )
        return fallback_path


def _receipt_event(
    item: Alert,
    key: str,
    delivery: SinkDelivery,
    attempted_at: datetime,
    *,
    live: bool,
) -> dict[str, object]:
    return {
        "timestamp": _iso(attempted_at),
        "alert_created_at": _iso(item.created_at),
        "severity": item.severity,
        "component": item.component,
        "summary": item.summary,
        "tags": list(item.tags),
        "details": _receipt_details(item.receipt_details),
        "sink": delivery.sink,
        "sink_live": live,
        "status": delivery.status,
        "success": delivery.success,
        "dry_run": delivery.dry_run,
        "dedup_skipped": delivery.dedup_skipped,
        "http_status": delivery.http_status,
        "failure_reason": delivery.failure_reason or None,
        "dedupe_key": key,
        "source": RECEIPT_SOURCE,
    }


def _receipt_details(details: Mapping[str, object] | None) -> object:
    """Persist only opted-in, bounded scalars. Nested values are dropped, never stringified."""

    if not details:
        return None
    safe: dict[str, object] = {}
    for key in sorted(details):
        value = details[key]
        if value is None or isinstance(value, bool):
            safe[key] = value
        elif isinstance(value, int):
            safe[key] = value
        elif isinstance(value, float) and math.isfinite(value):
            safe[key] = value
        elif isinstance(value, str):
            safe[key] = value[:MAX_RECEIPT_DETAIL_STRING_LENGTH]
    return safe or None


# --------------------------------------------------------------------------- dedupe
#
# A key moves claim -> confirmed on full delivery, or claim -> (removed) on failure. A claim
# carries an owner token, so a slow sender that finishes after its claim was reclaimed by
# another process cannot overwrite the newer owner's state. In-process claims age by the
# monotonic clock; durable (file) claims by wall clock, so different processes can compare.


@dataclass(frozen=True)
class _DedupEntry:
    timestamp: datetime
    state: str  # "claim" | "confirmed"
    acquired_at: float | None = None
    owner: str | None = None


_DEDUP_CACHE: OrderedDict[str, _DedupEntry] = OrderedDict()
_DEDUP_LOCK = threading.Lock()


def reset_dedup_state() -> None:
    """Clear in-process dedupe state (tests and one-shot tools)."""

    with _DEDUP_LOCK:
        _DEDUP_CACHE.clear()


def _active(entry: _DedupEntry, now: datetime, window: int, ttl: float, clock: float) -> bool:
    if entry.state == "claim":
        return entry.acquired_at is not None and clock - entry.acquired_at <= ttl
    elapsed = (now - entry.timestamp).total_seconds()
    return 0 <= elapsed < window


def _cap(entries: OrderedDict[str, _DedupEntry]) -> OrderedDict[str, _DedupEntry]:
    while len(entries) > MAX_DEDUP_ENTRIES:
        entries.popitem(last=False)
    return entries


@contextlib.contextmanager
def _locked_state(path: Path) -> Iterator[tuple[int, OrderedDict[str, _DedupEntry]]]:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        raw = b""
        while chunk := os.read(fd, 1 << 20):
            raw += chunk
        text = raw.decode("utf-8", errors="replace")
        if text.strip() and not _is_valid_state(text):
            # Fail toward SENDING (an empty dedupe table suppresses nothing), but never silently:
            # keep the unreadable file for inspection before it is rewritten, and say so.
            keep = path.with_name(path.name + ".corrupt")
            keep.write_bytes(raw)
            print(f"honest-watchdogs alerts: dedupe state {path} was unreadable; preserved it as "
                  f"{keep} and continued with an empty table (alerts are not suppressed)",
                  file=sys.stderr)
        yield fd, _entries_from_json(text)
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _is_valid_state(raw: str) -> bool:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return False
    return isinstance(data, dict) and isinstance(data.get("entries"), dict)


def _entries_from_json(raw: str) -> OrderedDict[str, _DedupEntry]:
    entries: OrderedDict[str, _DedupEntry] = OrderedDict()
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return entries
    items = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(items, dict):
        return entries
    for key, value in items.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            continue
        state = value.get("state")
        stamp = value.get("timestamp")
        if state not in ("claim", "confirmed") or not isinstance(stamp, str):
            continue
        try:
            timestamp = _as_utc(datetime.fromisoformat(stamp.replace("Z", "+00:00")))
        except ValueError:
            continue
        acquired = value.get("acquired_at")
        owner = value.get("owner")
        entries[key] = _DedupEntry(
            timestamp,
            state,
            float(acquired) if isinstance(acquired, (int, float)) else None,
            owner if isinstance(owner, str) else None,
        )
    return entries


def _write_entries(fd: int, entries: OrderedDict[str, _DedupEntry]) -> None:
    body = {
        "version": 1,
        "entries": {
            key: {
                "state": e.state,
                "timestamp": _iso(e.timestamp),
                **({"acquired_at": e.acquired_at, "owner": e.owner} if e.state == "claim" else {}),
            }
            for key, e in entries.items()
        },
    }
    data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    os.write(fd, data)
    os.fsync(fd)


def _prune(entries: OrderedDict[str, _DedupEntry], now: datetime, window: int, ttl: float,
           clock: float) -> OrderedDict[str, _DedupEntry]:
    return _cap(OrderedDict(
        (k, e) for k, e in entries.items() if _active(e, now, window, ttl, clock)
        or (e.state == "confirmed" and (now - e.timestamp).total_seconds() < 0)
    ))


def _dedup_claim(key: str, now: datetime, window: int, owner: str, *,
                 state_path: Path | None, claim_ttl_seconds: float) -> bool:
    """Return True when ``key`` is already active (skip); otherwise claim it."""

    if state_path is None:
        with _DEDUP_LOCK:
            clock = time.monotonic()
            previous = _DEDUP_CACHE.get(key)
            if previous is not None and _active(previous, now, window, claim_ttl_seconds, clock):
                _DEDUP_CACHE.move_to_end(key)
                return True
            _DEDUP_CACHE[key] = _DedupEntry(now, "claim", clock, owner)
            _DEDUP_CACHE.move_to_end(key)
            _cap(_DEDUP_CACHE)
            return False
    with _locked_state(state_path) as (fd, entries):
        clock = time.time()
        entries = _prune(entries, now, window, claim_ttl_seconds, clock)
        previous = entries.get(key)
        if previous is not None and _active(previous, now, window, claim_ttl_seconds, clock):
            _write_entries(fd, entries)
            return True
        entries[key] = _DedupEntry(now, "claim", clock, owner)
        entries.move_to_end(key)
        _write_entries(fd, _cap(entries))
        return False


def _dedup_confirm(key: str, now: datetime, window: int, owner: str, *,
                   state_path: Path | None, claim_ttl_seconds: float) -> None:
    if state_path is None:
        with _DEDUP_LOCK:
            previous = _DEDUP_CACHE.get(key)
            if previous is not None and previous.state == "claim" and previous.owner == owner:
                _DEDUP_CACHE[key] = _DedupEntry(now, "confirmed")
                _DEDUP_CACHE.move_to_end(key)
        return
    with _locked_state(state_path) as (fd, entries):
        previous = entries.get(key)
        # Delivery completion owns its claim even if it finished after the claim TTL.
        if previous is not None and previous.state == "claim" and previous.owner == owner:
            entries[key] = _DedupEntry(now, "confirmed")
            entries.move_to_end(key)
        protected = entries.pop(key, None)
        entries = _prune(entries, now, window, claim_ttl_seconds, time.time())
        if protected is not None:
            entries[key] = protected
        _write_entries(fd, _cap(entries))


def _dedup_release(key: str, now: datetime, window: int, owner: str, *,
                   state_path: Path | None, claim_ttl_seconds: float) -> None:
    if state_path is None:
        with _DEDUP_LOCK:
            previous = _DEDUP_CACHE.get(key)
            if previous is not None and previous.state == "claim" and previous.owner == owner:
                del _DEDUP_CACHE[key]
        return
    with _locked_state(state_path) as (fd, entries):
        entries = _prune(entries, now, window, claim_ttl_seconds, time.time())
        previous = entries.get(key)
        if previous is not None and previous.state == "claim" and previous.owner == owner:
            del entries[key]
        _write_entries(fd, entries)


# --------------------------------------------------------------------------- helpers


def _single_line(value: object) -> str:
    return " ".join(str(value).split())


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _iso(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _normalize_tags(tags: Iterable[str]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for tag in tags:
        key = "-".join(
            part for part in "".join(
                c if c.isalnum() else " " for c in _single_line(tag).lower()
            ).split()
        )
        if key:
            seen.setdefault(key, None)
    return tuple(seen)


def _details_text(details: Mapping[str, object] | str | None) -> str:
    if details is None:
        return ""
    if isinstance(details, str):
        return details.strip()
    return json.dumps(details, sort_keys=True, default=str)


def _response_status(response: object) -> int:
    getcode = getattr(response, "getcode", None)
    if callable(getcode):
        code = getcode()
        if isinstance(code, int):
            return code
    status = getattr(response, "status", None)
    return int(status) if isinstance(status, int) else 200


def _reason_text(reason: object) -> str:
    if isinstance(reason, OSError):
        # The exception type names the cause (for example a certificate verification error)
        # without echoing a URL, which may carry a secret token.
        return type(reason).__name__
    text = _single_line(str(reason))
    return text[:160] if text else "unknown"


def _float(source: Mapping[str, str], key: str, default: float) -> float:
    raw = _single_line(source.get(key, ""))
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise AlertConfigError(f"{key} must be a number") from exc


# --------------------------------------------------------------------------- CLI


def main(argv: list[str] | None = None) -> int:
    """Send one alert through the configured sinks: a positive control for the alert path.

    Exit 0 if every sink delivered (or dry-ran with --dry-run), 1 if any sink failed,
    2 if the configuration is invalid.
    """

    parser = argparse.ArgumentParser(
        prog="watchdog-alert",
        description="Send one alert through the configured sinks and print the receipt path. "
        "Use it to prove the alert path can fire before you trust a detector that relies on it.",
    )
    parser.add_argument("summary")
    parser.add_argument("--severity", default="info", choices=SEVERITIES)
    parser.add_argument("--component", default="watchdog-alert")
    parser.add_argument("--dedupe-key")
    parser.add_argument("--tag", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true",
                        help="print the delivery report to stdout instead of stderr")
    args = parser.parse_args(argv)
    try:
        result = alert(
            args.severity, args.component, args.summary,
            dedupe_key=args.dedupe_key, tags=args.tag, dry_run=args.dry_run,
        )
    except AlertConfigError as exc:
        print(f"watchdog-alert: {exc}", file=sys.stderr)
        return EXIT_MISCONFIGURED
    report = {
        "dedupe_key": result.dedupe_key,
        "receipt_path": str(result.receipt_path),
        "deliveries": [
            {"sink": d.sink, "status": d.status, "http_status": d.http_status,
             "failure_reason": d.failure_reason or None}
            for d in result.deliveries
        ],
    }
    print(json.dumps(report, sort_keys=True), file=sys.stdout if args.json else sys.stderr)
    return EXIT_OK if result.success else EXIT_FINDINGS


if __name__ == "__main__":
    raise SystemExit(main())
