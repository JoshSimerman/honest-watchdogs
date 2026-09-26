# Design decisions

Each entry states the context, the decision, what it costs, and what I would revisit. These
instruments were written for a small group of macOS and Linux machines running a few dozen
scheduled jobs, alerting a chat channel. Every rule below was added after its absence let a real
failure go unreported; the incidents are described by shape, not by name.

---

## ADR-001: One exit-code convention, with UNKNOWN distinct from OK

**Context.** A scheduler, a shell pipeline and a human all read `$?` before they read output. The
classic monitoring bug is a check that cannot reach its target, catches the exception, and exits
0: an unreachable machine reads as a healthy one.

**Decision.** `0` OK, `1` findings, `2` misconfigured, `3` UNKNOWN, for every instrument. UNKNOWN
outranks findings when both occur (`exitcodes.combine` states the rule, and each instrument
applies it). Anything that prevents measurement (ssh failure, empty inventory, unparseable
output, corrupt state, a crashed probe worker) is `3`.

**Consequences.**
- Callers can alert on `3` separately from `1`: "the watch is blind" is a different page from
  "the watch saw something".
- `2` doubles as argparse's usage-error code, which is the same idea (the instrument was invoked
  wrongly).
- The crash-loop watch keeps one exception: a crash loop that was paged successfully exits `0`
  by default, because the watch is itself a launchd job and must not look like a crash loop of its
  own. `--fail-on-crash-loop` restores `1`.

**Revisit.** A structured "partial coverage" code might be clearer than folding it into `3`.

---

## ADR-002: Positive controls and red-on-revert tests are part of the instrument

**Context.** A detector's tests usually show that a healthy system reads healthy. That is the
half that never matters. A detector that has never been shown to fire gives no information when
it stays quiet.

**Decision.** Every instrument's suite contains MUST-FIRE tests that construct the failure it
exists for, and every guard has been checked red-on-revert: disable the guard, and a named test
fails. (Doing that check while writing this repository found one guard, the mount probe's write,
that no test covered; a test was added.) Tests that need a blocking syscall use a real one (a
FIFO, a sleeping subprocess) rather than a mock that cannot block.

The mount probe extends this to runtime: it performs its write against local disk through the
same machinery before it may call the mount unhealthy.

**Consequences.** Tests are larger and slower than pure unit tests (the suite starts real
subprocesses and an HTTP server). Test names read as requirements.

---

## ADR-003: Expected periods come from the declaration, never from observation

**Context.** Two jobs have been running for a day. One is a daemon (fine); the other is an hourly
job that hung (broken). Uptime cannot tell them apart. And any bound derived from observed
behaviour ("it usually takes N") can be stretched by the failure itself: a stuck job enlarges its
own history.

**Decision.** The wedge watch reads plists (`StartInterval`, `StartCalendarInterval`,
`KeepAlive`); the timer checker reads unit files through `systemctl cat` and resolves them with
`systemd-analyze`. Where a job's own script declares a runtime (`expect ~10 min`), that beats the
cadence, because a cadence says how often work starts, not how long it takes.

**Consequences.**
- Jobs with ambiguous declarations (a schedule *and* `KeepAlive`; only `OnBootSec=`) are UNKNOWN
  rather than guessed at.
- The declared-runtime convention is a comment in a script. It is capped at 24 hours and floored
  at five minutes because it is a claim, not a measurement.

**Revisit.** A plist key or unit property for expected runtime would beat a regex over a script.

---

## ADR-004: Suppress false alarms by modelling the schedule, not by raising thresholds

**Context.** A watch that pages on correct behaviour gets muted, and a muted watch is worse than
none: people believe it is watching. The tempting fix is a bigger multiplier. It trades false
alarms for late detection everywhere.

**Decision.** Model the specific legitimate cases:
- windowed timers: confirm "overdue" against the declared calendar evaluated from the last
  trigger, and keep the longest declared gap (weekends, month boundaries);
- timers that have not reached their first elapse, or are inactive: separate buckets, reported but
  not paged;
- jobs whose contract is a non-zero exit on findings: an explicit, per-label, schedule-gated
  exemption;
- deliberate restarts: signals end a crash-loop pattern instead of extending it.

Every such exemption can only remove a finding when its own evidence resolves cleanly. If the
calendar re-resolution fails, the finding stands.

**Consequences.** More code paths than a threshold, each with a test that shows the exemption
does not swallow the real failure next to it (a windowed timer that stops *inside* its window
still fires).

---

## ADR-005: Alert until it is over, and only latch on delivery

**Context.** Alert-once is right for a condition that ends. For one that does not, the first page
is also the last, and an incident that pages once and then runs for a week is indistinguishable,
to everyone, from one that was fixed. Separately, a latch set when a page was *attempted* turns a
broken alert path into silence.

**Decision.** Reminder intervals (default six hours) on every instrument that latches. Latches
and dedupe keys advance only on successful delivery; a failed delivery leaves the condition due
on the next run, and its error record carries each sink's failure reason.

**Consequences.** A persistently failing alert path retries every run; that is intended, since
the receipts will show every attempt and why it failed.

---

## ADR-006: Receipts are mandatory, bounded, and never silently dropped

**Context.** "The alert was sent" usually means a function returned. The receipt log is how you
answer "did anyone get told?" after the fact. But if the receipt directory is on a network
mount, writing the receipt can hang the watchdog indefinitely, at exactly the moment it has
something to report.

**Decision.** One JSONL line per sink per attempt, with the receiver's status. The write runs
under a `SIGALRM` deadline; on timeout or error the line goes to a local fallback directory,
marked degraded with the intended path and the reason, plus a stderr warning. The fallback is
triggered by attempting the write, never by an existence check, because permission layers can
allow metadata while denying content. The fallback write has the same deadline. If it fails too,
the full receipt line is printed to stderr under `ALERT RECEIPT LOST`, the delivery carries a
`receipt_error`, and `watchdog-alert` exits 1. A receipt failure never raises out of the delivery
loop: the remaining sinks are always attempted, because a receipt is bookkeeping about a page and
must not prevent the next one.

**Consequences.** `SIGALRM` bounds the write only on the main thread; off it the write is
unbounded, and that is documented rather than disguised. Receipts persist only opted-in scalar
context, so they can be kept longer and shared more widely than alert bodies. A delivered page
whose receipt was lost still counts as delivered for latching (`result.success`), so the human is
not paged again; `result.receipts_ok` reports the loss separately. With stderr closed as well,
the receipt is gone, and only `receipt_error` on the result records that it was.

---

## ADR-007: A test suite must not be able to page a human

**Context.** Tests for alerting code tend to exercise the real sender. Eventually one runs with
real configuration in the environment, and a person gets paged by a temp-directory fixture.
Human care does not fix this; a test nobody is watching can do it.

**Decision.** The single function every alert passes through suppresses live sinks when
`PYTEST_CURRENT_TEST` is set, prints why on stderr, and records `dry_run` receipts. Exactly
`HONEST_WATCHDOGS_ALLOW_LIVE=1` overrides it, for deliberately proving a detector against a live
channel; without an override, the next person who needs one deletes the guard.

**Consequences.** The suppression is loud, never silent: a silent one would create the opposite
defect, a detector that believes it paged.

---

## ADR-008: The guarded mirror refuses on shape

**Context.** The owner of a directory deletes files on purpose; a bug deletes files by accident.
To `rsync --delete` they look identical, and an append-only copy would resurrect deliberate
deletions.

**Decision.** Mirror with `--delete`, but refuse the run, leaving the previous mirror intact,
when the change has the shape of a wipe: too many deletions at once, a deletion without an index
edit, a deleted or truncated index, or an empty source. Copy to staging, re-list the source after
the copy, verify per file both ways, swap atomically, and keep dated snapshots outside the
mirror's delete path.

**Consequences.** Legitimate bulk reorganisations are refused until someone raises
`--max-deletions` for one run. That is the intended trade: one stale day against the only copy.

**Revisit.** The index-file heuristic fits directories that have an index. Other layouts would
need a different notion of "shape".

---

## ADR-009: Probe mounts with a bounded write in a separate process

**Context.** The mount table and a directory listing both say a network share is fine long after
its server is gone. The first real `open()` then blocks in the kernel, where neither an exception
handler nor a thread can reach it.

**Decision.** Every probe runs in a fresh interpreter in its own process group, killed at a hard
deadline, and the parent never waits unboundedly even after the kill. The write probe (create and
remove a uniquely named directory) is the one that has to reach the server. A local positive
control runs first. Remediation is opt-in, bounded, re-probes before every destructive step and
refuses on any verdict it cannot trust, and a missing known file is `misconfigured`, not
`unresponsive`, so it can never trigger a force-unmount.

**Consequences.** Each probe costs an interpreter start (tens of milliseconds). The verdict covers
one binary, and the report says so, because file access can be granted per binary.

---

## ADR-010: Standard library only; every external command behind a replaceable function

**Context.** Monitoring code runs on the machines least able to afford a dependency problem, and
has to be testable on machines that do not have launchd, systemd or the remote host.

**Decision.** No third-party dependencies. Every call to `launchctl`, `ps`, `systemctl`,
`systemd-analyze`, `ssh` or `rsync` goes through one module-level function that tests replace, and
those fakes match exact command strings, so a change in what the instrument sends fails a test.

**Consequences.** The suite runs anywhere POSIX. The parsers are tested against captured command
output (with names and paths neutralised), not against synthetic minimal strings, because the
nested fields in real `launchctl print` output are what a naive parser gets wrong.
