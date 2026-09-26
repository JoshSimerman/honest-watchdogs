# Alerts

`honest_watchdogs.alerts` is the delivery layer every instrument uses. It is also a command,
`watchdog-alert`, which sends one alert through the configured sinks: run it before you trust any
detector that depends on it. It prints its delivery report to stderr, or to stdout with `--json`,
and exits 0 when every sink delivered and every receipt was written to a file, 1 when any sink
failed or any receipt was lost, 2 when the configuration is invalid.

## What it guarantees

| Guarantee | Mechanism |
|---|---|
| Every sink is attempted | Nothing in the delivery loop raises. A sink that raises or returns something other than a `DeliveryOutcome` is a failed delivery; a receipt or dedupe-file failure is recorded on the result and printed to stderr; a closed stderr is ignored. The next sink is always tried |
| Every attempt leaves evidence | One JSONL receipt line per sink per alert, in `<receipt_dir>/<YYYY-MM-DD>-alerts.jsonl` |
| "Sent" is distinguished from "delivered" | A receipt's `status` is `delivered` only when the sink acknowledged (for a webhook: HTTP 2xx). Otherwise `failed`, with `failure_reason` and `http_status` |
| A wedged receipt directory cannot hang the watchdog | The receipt write runs under a `SIGALRM` deadline; on timeout or `OSError` it goes to a local fallback directory with `receipt_degraded: true` and the intended path. The fallback write has the same deadline |
| A receipt is never dropped silently | The deadline changes the destination, never whether to record. If the fallback fails too, the full receipt line goes to stderr under `ALERT RECEIPT LOST`, the delivery carries `receipt_error`, and `result.receipts_ok` is False |
| A failed page stays retryable | Dedupe keys are claimed, confirmed only when every sink delivered, released otherwise |
| A crashed sender cannot suppress a key for long | Claims expire after `CLAIM_TTL_SECONDS` (30s) |
| A test suite cannot page a human | Under pytest, live sinks are forced to dry-run with a loud stderr message, unless `HONEST_WATCHDOGS_ALLOW_LIVE=1` |
| Secrets in webhook URLs stay out of logs | Failure reasons name the exception type, never the URL |
| A corrupt dedupe file cannot suppress alerts | An unparseable `WATCHDOG_DEDUP_STATE` file is copied to `<file>.corrupt`, reported on stderr, and replaced by an empty table: the failure direction is *sending* |

## Flow

```mermaid
flowchart TD
    A[alert] --> B{dry run?}
    B -- no --> C{dedupe key active?<br/>claim or confirmed}
    C -- yes --> S[record dedup_skipped receipt per sink]
    C -- no --> D[claim key with owner token]
    C -- "dedupe file unusable" --> E
    D --> E[for each sink]
    B -- yes --> E
    E --> F{live sink and<br/>live delivery blocked?}
    F -- yes --> G[dry_run delivery]
    F -- no --> H["sink.deliver<br/>(raise or garbage = failed)"]
    G --> R[append receipt, bounded by deadline]
    H --> R
    R -- write blocked or failed --> FB[append to local fallback,<br/>same deadline, warn on stderr]
    FB -- also fails --> L[receipt line to stderr,<br/>ALERT RECEIPT LOST, receipt_error]
    R --> N{more sinks?}
    FB --> N
    L --> N
    N -- yes --> E
    N -- no --> I{all sinks delivered?}
    I -- yes --> J[confirm claim: key suppressed for the window]
    I -- no --> K[release claim: next attempt retries]
```

## Checking the alert path

`watchdog-alert` is the positive control for the alert path. A webhook that answers 503 is a
failed delivery, the receipt says so, and the command exits 1:

```mermaid
sequenceDiagram
    autonumber
    actor Op as operator
    participant CLI as watchdog-alert
    participant A as alerts.send_alert
    participant D as dedupe table
    participant S as sink (webhook)
    participant R as receipts JSONL
    Op->>CLI: --severity critical "path check"
    CLI->>A: alert(...)
    A->>D: claim key (owner token, 30s TTL)
    A->>S: deliver(alert)
    S-->>A: HTTP 503
    A->>R: append receipt, status=failed (SIGALRM deadline)
    alt every sink delivered
        A->>D: confirm: suppressed for the window
    else any sink failed
        A->>D: release: next run retries
    end
    A-->>CLI: AlertResult
    CLI-->>Op: delivery report, exit 1
```

![watchdog-alert with no configuration delivers to stderr and exits 0; pointed at a webhook that answers 503 it exits 1, and the receipt records status failed and failure_reason HTTP 503](images/alert-path-check.png)

## Dedupe states

A dedupe key moves through three states. Only full delivery confirms it, so a failed page cannot
suppress the next attempt:

```mermaid
stateDiagram-v2
    [*] --> claim: first sender claims
    claim --> confirmed: every sink delivered
    claim --> [*]: any sink failed (released)
    claim --> [*]: claim older than 30s (abandoned)
    confirmed --> [*]: dedupe window elapsed (default 600s)
    note right of claim
        a live claim or a confirmed key
        makes other senders skip
        (receipt status dedup_skipped)
    end note
```

Above the library, the instruments keep their own latches (`--reminder-seconds`, default six
hours) that also advance only on delivery.

## Sinks

A sink is any object with `name: str`, `live: bool` and `deliver(alert) -> DeliveryOutcome`.

- `StdoutSink`, `StderrSink`: one JSON line per alert. Not live.
- `WebhookSink(url, payload_format="json" | "text", timeout_seconds=5, headers=None)`: a POST.
  `json` sends the alert's fields (`severity`, `component`, `summary`, `details`, `dedupe_key`,
  `tags`, `created_at`). `text` sends `{"text": "SEVERITY [component] summary"}`, a shape many
  chat webhooks accept. Live.

Write your own for anything else (a pager API, a message queue): return
`DeliveryOutcome(success=False, failure_reason=...)` on failure rather than raising. A sink that
raises is recorded as a failed delivery, not a crash.

## Receipts

```json
{"timestamp": "2030-01-01T09:00:01Z", "alert_created_at": "2030-01-01T09:00:00Z",
 "severity": "critical", "component": "systemd-timer-liveness",
 "summary": "timer backup.timer on db1 is overdue: ...", "tags": ["systemd", "timer-liveness"],
 "details": null, "sink": "webhook", "sink_live": true, "status": "failed", "success": false,
 "dry_run": false, "dedup_skipped": false, "http_status": 503, "failure_reason": "HTTP 503",
 "dedupe_key": "systemd-timer-liveness/overdue/db1/backup.timer", "source": "honest-watchdogs"}
```

Receipts are dated by the **attempt** time, not the alert's creation time, so a stale or
mis-dated alert still lands in today's file where someone will look.

`details` is delivered to sinks but **not** persisted. To persist context, pass
`receipt_details=`; only scalars survive (strings truncated to 256 characters, nested values
dropped). Receipts tend to be kept longer and read more widely than alerts.

## Design notes

**Why SIGALRM and not a thread?** A thread cannot interrupt a blocked `open()`, and a subprocess
per receipt is too expensive for the alert path. `SIGALRM` interrupts the syscall on the main
thread. Off the main thread the write runs unbounded; that limit is documented rather than
hidden.

**Why is the fallback triggered by a write and not an existence check?** Some permission layers
allow metadata operations while denying content. `path.exists()` returns True under exactly the
failure the fallback is for. Only attempting the write can tell you.

**Why does a dedupe skip count as `success`?** Callers latch on `result.success`. Inside the
dedupe window the condition was already delivered, so latching is correct. Use
`result.delivered` when you need to know that *this* call reached every sink.

**Why does a lost receipt not make `success` False?** `success` is what callers latch on. The
page reached the human; failing it would page them again on every run until the disk is fixed.
The loss is reported separately: stderr, `receipt_error`, `result.receipts_ok`, and
`watchdog-alert`'s exit status. A dedupe file that cannot be used fails toward sending: the alert
goes out without dedupe and `result.dedupe_error` says why.

**Why is dry-run `success`?** So a watchdog run with alerts suppressed still behaves like a
normal run. Dry-run never confirms a dedupe key, so it cannot consume the window of a real page.
