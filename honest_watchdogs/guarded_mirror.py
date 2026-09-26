"""Mirror indexed directories with rsync, refusing to overwrite good data with truncated data.

Works on macOS and Linux; needs ``rsync`` locally and ``ssh`` for remote hosts. Discovers every
directory matching ``--source-glob`` on each host (default: AI-agent memory directories,
``~/.claude/projects/*/memory``, each carrying a ``MEMORY.md`` index) and mirrors each one to
``<destination>/<host>-<slug>/``.

THE DESIGN CONSTRAINT: a plain ``rsync --delete`` is wrong, and a plain append-only copy is also
wrong. The owner of a directory legitimately DELETES a file it discovers was incorrect, and the
mirror must not resurrect it; but a bug that empties the directory must not propagate either.
Those look identical to rsync. They differ in SHAPE, so this tool refuses on shape:

    A LEGITIMATE delete is one file, occasionally two, AND comes with an edit to the index file
    removing that entry.
    A BUG is N files at once with the index untouched, or the index truncated.

So it mirrors with ``--delete`` but REFUSES THE RUN, leaving the previous mirror intact, when
deletions exceed ``--max-deletions``, when any deletion comes with no index edit, when the index
is deleted, or when the index shrinks by more than ``--max-index-shrink`` lines. On top of that,
a dated snapshot per directory lives OUTSIDE the rsync target and is never pruned here: a mirror
with any delete path, however guarded, must not be the only copy.

Success is measured by effect, both ways: the source is hashed per file, the copy is re-hashed
per file, and every divergence names its file. Hash output is normalized to ``(hash, path)``
pairs before comparison, because ``sha256sum`` (Linux) and ``shasum -a 256`` (macOS) format
differently and comparing raw output reports a mismatch that does not exist.

Exit status: 0 every reachable directory mirrored and verified; 1 a shape guard refused at
least one (mirror left intact); 3 a host was unreachable, a destination unwritable, or
verification could not confirm parity. An unreachable host is UNKNOWN for that host, never a
silent skip; other hosts are still mirrored.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from ._state import StateCorrupt, load_json_state, save_json_state
from .alerts import alert
from .exitcodes import EXIT_FINDINGS, EXIT_MISCONFIGURED, EXIT_OK, EXIT_UNKNOWN

DEFAULT_SOURCE_GLOB = "~/.claude/projects/*/memory"
DEFAULT_INDEX_NAME = "MEMORY.md"
DESTINATION_ENV = "WATCHDOG_MIRROR_DESTINATION"
DEFAULT_MAX_DELETIONS = 2
# A legitimate index edit occasionally drops a line while rewording; more shrinkage than this
# is the truncation shape, not an edit.
DEFAULT_MAX_INDEX_SHRINK = 2
DEFAULT_TIMEOUT = 120.0
DEFAULT_REMINDER_SECONDS = 21600.0
DEFAULT_STATE_FILE = "~/.local/state/honest-watchdogs/guarded-mirror.json"
MANIFEST_NAME = "MANIFEST.sha256"
SNAPSHOTS_DIRNAME = "snapshots"
WORK_DIRNAME = "._work"

_FILES_BEGIN = "__HW_MIRROR_FILES__"
_INDEX_BEGIN = "__HW_MIRROR_INDEX__"
_DONE = "__HW_MIRROR_DONE__"
_NO_INDEX = "__HW_MIRROR_NO_INDEX__"

# sha256sum and shasum -a 256 emit "<hash> <mode><path>" with mode ' ' or '*'; openssl emits
# the BSD form. Anything else is a parse error, surfaced as UNKNOWN rather than skipped.
_GNU_HASH_LINE = re.compile(r"^([0-9a-f]{64}) [ *](.+)$")
_BSD_HASH_LINE = re.compile(r"^SHA256 \((.+)\) = ([0-9a-f]{64})$")
_SAFE_GLOB = re.compile(r"^[A-Za-z0-9._/*?~+-]+$")

README_TEXT = """\
# guarded mirror

WHAT THIS IS: a scheduled, per-file sha256-verified mirror. Each `<host>-<slug>/` directory
mirrors one source directory as of the last successful run, and carries a `MANIFEST.sha256`
in `sha256sum -c` format.

WHAT THIS IS NOT: version control or an append-only archive. Small deletions that come with
an index edit propagate; bulk deletions and index truncation are REFUSED and leave the
previous mirror intact. It is also not the only copy: `snapshots/<host>-<slug>/<YYYY-MM-DD>/`
holds dated recovery points that the mirror's delete path never touches and that this tool
never prunes.
"""


@dataclass(frozen=True)
class Corpus:
    host: str
    path: str
    slug: str

    @property
    def dest_name(self) -> str:
        return f"{self.host}-{self.slug}"


@dataclass(frozen=True)
class Listing:
    """Normalized view of one directory: relpath -> sha256, plus the index's line count."""

    files: dict[str, str]
    index_sha: str | None = None
    index_lines: int | None = None


@dataclass
class CorpusOutcome:
    corpus: Corpus
    status: str  # "ok" | "refused" | "unknown"
    reason: str = ""
    findings: dict = field(default_factory=dict)


@dataclass(frozen=True)
class MirrorSettings:
    source_glob: str = DEFAULT_SOURCE_GLOB
    index_name: str = DEFAULT_INDEX_NAME
    max_deletions: int = DEFAULT_MAX_DELETIONS
    max_index_shrink: int = DEFAULT_MAX_INDEX_SHRINK
    timeout: float = DEFAULT_TIMEOUT


def local_hostname() -> str:
    return socket.gethostname().split(".")[0]


def is_local(host: str) -> bool:
    return host in (local_hostname(), "localhost", "local")


def slugify(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")
    return slug or "unnamed"


def corpus_slug(path: str, pattern: str = DEFAULT_SOURCE_GLOB) -> str:
    """Name a matched directory by the path components its glob wildcards matched.

    ``~/.claude/projects/*/memory`` matching ``.../projects/web-app/memory`` gives ``web-app``.
    Components are aligned from the END, because ``*`` never crosses ``/`` and the home directory
    differs in length from host to host.
    """

    tail = Path(pattern[2:] if pattern.startswith("~/") else pattern.lstrip("/")).parts
    parts = Path(path).parts
    matched = parts[-len(tail):] if len(parts) >= len(tail) else parts
    wild = [m for g, m in zip(tail, matched) if any(c in g for c in "*?")]
    return slugify("-".join(wild) if wild else Path(path).name)


def run_ssh(host: str, remote_command: str, timeout: float) -> tuple[int, str, str]:
    """Run one remote command without turning transport failure into silence."""

    try:
        proc = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host, remote_command],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return -1, "", f"ssh to {host} timed out after {timeout}s"
    except Exception as exc:  # any launch failure is UNKNOWN, never OK
        return -1, "", f"could not run ssh: {exc}"
    return proc.returncode, proc.stdout, proc.stderr


def run_rsync(argv: list[str], timeout: float) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return -1, "", f"rsync timed out after {timeout}s"
    except Exception as exc:
        return -1, "", f"could not run rsync: {exc}"
    return proc.returncode, proc.stdout, proc.stderr


def validate_glob(pattern: str) -> str:
    if not _SAFE_GLOB.fullmatch(pattern) or not pattern.startswith(("~/", "/")):
        raise ValueError(
            "--source-glob must start with '~/' or '/' and use only letters, digits, "
            "'.', '_', '-', '+', '/', '*', '?'"
        )
    if ".." in Path(pattern).parts:
        raise ValueError("--source-glob must not contain '..'")
    return pattern


def discover_corpora(host: str, settings: MirrorSettings) -> tuple[list[Corpus], str]:
    """Expand the source glob on the host; empty list plus a reason on failure.

    Discovery is by glob, never a hardcoded list: directories move between machines, and a
    fixed list silently stops covering the one that moved.
    """

    pattern = settings.source_glob
    if is_local(host):
        expanded = os.path.expanduser(pattern)
        try:
            root = Path(expanded).anchor or "/"
            rel = os.path.relpath(expanded, root)
            matches = sorted(Path(root).glob(rel))
        except (OSError, ValueError) as exc:
            return [], f"cannot glob {pattern}: {exc}"
        return [Corpus(host=host, path=str(m), slug=corpus_slug(str(m), pattern)) for m in matches if m.is_dir()], ""

    remote_pattern = '"$HOME"/' + pattern[2:] if pattern.startswith("~/") else pattern
    remote_command = f'for d in {remote_pattern}; do if [ -d "$d" ]; then printf "%s\\n" "$d"; fi; done'
    rc, stdout, stderr = run_ssh(host, remote_command, settings.timeout)
    if rc != 0:
        return [], (
            f"ssh to {host} failed discovering directories (rc={rc}): "
            f"{stderr.strip()[:200] or 'no stderr'}"
        )
    corpora = [
        Corpus(host=host, path=line.strip(), slug=corpus_slug(line.strip(), pattern))
        for line in stdout.splitlines()
        if line.strip().startswith("/")
    ]
    return corpora, ""


def build_listing_command(corpus_path: str, index_name: str) -> str:
    """One framed remote command: per-file hashes plus the index's line count.

    The hasher is chosen on the remote host, so the same command works on Linux and macOS.
    Files are hashed one per process rather than via xargs, so an EMPTY directory cannot make
    the hasher read stdin and hang (BSD xargs has no ``-r``).
    """

    quoted = shlex.quote(corpus_path)
    index = shlex.quote(f"./{index_name}")
    return (
        f"cd {quoted} || {{ echo {_DONE}; exit 1; }}; "
        f"echo {_FILES_BEGIN}; "
        "if command -v sha256sum >/dev/null 2>&1; then "
        '__hw_hash() { sha256sum "$1"; }; else '
        '__hw_hash() { shasum -a 256 "$1"; }; fi; '
        "find . -type f -print | LC_ALL=C sort | "
        'while IFS= read -r __hw_f; do __hw_hash "$__hw_f" || exit 1; done; '
        f"echo {_INDEX_BEGIN}; "
        f'if [ -f {index} ]; then wc -l < {index} | tr -d " "; '
        f"else echo {_NO_INDEX}; fi; "
        f"echo {_DONE}"
    )


def parse_hash_lines(text: str) -> dict[str, str]:
    """Normalize sha256sum/shasum/openssl output to ``{relpath: hash}``.

    Anything unrecognizable raises ValueError: a parse failure must read as UNKNOWN, never as a
    silently smaller directory.
    """

    files: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        match = _GNU_HASH_LINE.match(line)
        if match:
            digest, path = match.group(1), match.group(2)
        else:
            bsd = _BSD_HASH_LINE.match(line)
            if not bsd:
                raise ValueError(f"unparseable hash line: {line[:120]!r}")
            path, digest = bsd.group(1), bsd.group(2)
        relpath = path[2:] if path.startswith("./") else path
        if not relpath or relpath.startswith("/") or ".." in Path(relpath).parts:
            raise ValueError(f"unsafe relpath in hash line: {path[:120]!r}")
        files[relpath] = digest
    return files


def fetch_remote_listing(host: str, corpus_path: str, settings: MirrorSettings) -> tuple[Listing | None, str]:
    rc, stdout, stderr = run_ssh(host, build_listing_command(corpus_path, settings.index_name),
                                 settings.timeout)
    if rc != 0:
        return None, f"ssh to {host} failed listing {corpus_path} (rc={rc}): {stderr.strip()[:200]}"
    if _DONE not in stdout:
        return None, f"remote listing of {corpus_path} produced no completion marker"
    sections = stdout.split(f"{_FILES_BEGIN}\n", 1)
    if len(sections) != 2:
        return None, f"remote listing of {corpus_path} is missing its file section"
    body = sections[1]
    if body.startswith(f"{_INDEX_BEGIN}\n"):
        files_text, rest = "", body[len(f"{_INDEX_BEGIN}\n"):]
    else:
        files_text, _, rest = body.partition(f"\n{_INDEX_BEGIN}\n")
        if not rest:
            return None, f"remote listing of {corpus_path} is missing its index section"
    index_text = rest.rsplit(f"\n{_DONE}", 1)[0].strip()
    try:
        files = parse_hash_lines(files_text)
    except ValueError as exc:
        return None, f"remote listing of {corpus_path} could not be parsed: {exc}"
    if index_text == _NO_INDEX:
        return Listing(files=files), ""
    try:
        index_lines = int(index_text)
    except ValueError:
        return None, f"remote line count of {settings.index_name} is not an integer: {index_text[:80]!r}"
    return Listing(files=files, index_sha=files.get(settings.index_name), index_lines=index_lines), ""


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def local_listing(corpus_dir: Path, index_name: str = DEFAULT_INDEX_NAME) -> Listing:
    files: dict[str, str] = {}
    for path in sorted(corpus_dir.rglob("*")):
        if not path.is_file():
            continue
        relpath = path.relative_to(corpus_dir).as_posix()
        if relpath == MANIFEST_NAME:
            continue  # only this tool writes that name, and only into mirrors
        files[relpath] = hash_file(path)
    index_path = corpus_dir / index_name
    index_lines = index_path.read_bytes().count(b"\n") if index_path.is_file() else None
    return Listing(files=files, index_sha=files.get(index_name), index_lines=index_lines)


def fetch_source_listing(corpus: Corpus, settings: MirrorSettings) -> tuple[Listing | None, str]:
    if is_local(corpus.host):
        try:
            return local_listing(Path(corpus.path), settings.index_name), ""
        except OSError as exc:
            return None, f"cannot read local directory {corpus.path}: {exc}"
    return fetch_remote_listing(corpus.host, corpus.path, settings)


def refusal_reasons(
    source: Listing,
    dest: Listing | None,
    max_deletions: int,
    *,
    index_name: str = DEFAULT_INDEX_NAME,
    max_index_shrink: int = DEFAULT_MAX_INDEX_SHRINK,
) -> list[str]:
    """The shape guard: tell a legitimate delete from a wipe.

    A refusal leaves the PREVIOUS mirror byte-for-byte intact. The cost of a refusal is one stale
    day; the cost of a wrong propagation is the data. Every condition that fired is named.
    """

    if dest is None:
        return []
    reasons: list[str] = []
    deletions = sorted(set(dest.files) - set(source.files))
    if not source.files and dest.files:
        reasons.append(
            f"source is empty and the mirror holds {len(dest.files)} file(s); "
            f"refusing to propagate a wipe"
        )
    if len(deletions) > max_deletions:
        reasons.append(
            f"{len(deletions)} file deletions exceed the threshold of {max_deletions}: "
            f"{', '.join(deletions[:5])}"
        )
    index_changed = source.index_sha is not None and source.index_sha != dest.index_sha
    if deletions and not index_changed:
        reasons.append(f"{len(deletions)} file deletion(s) with no corresponding {index_name} edit")
    if dest.index_sha is not None and source.index_sha is None:
        reasons.append(f"{index_name} was deleted at the source")
    if (
        dest.index_lines is not None
        and source.index_lines is not None
        and dest.index_lines - source.index_lines > max_index_shrink
    ):
        reasons.append(
            f"{index_name} shrank from {dest.index_lines} to {source.index_lines} lines "
            f"(more than {max_index_shrink})"
        )
    return reasons


def build_rsync_argv(host: str, source_path: str, dest_dir: Path) -> list[str]:
    if is_local(host):
        source, ssh = f"{source_path}/", []
    else:
        source = f"{host}:{shlex.quote(source_path)}/"
        ssh = ["-e", "ssh -o BatchMode=yes -o ConnectTimeout=10"]
    # --checksum is load-bearing, not an optimization: rsync -a alone selects files by
    # size+mtime, so an edit that preserves both is never copied, and verification would report
    # a mismatch every run forever.
    return ["rsync", "-a", "--delete", "--checksum", *ssh, source, f"{dest_dir}/"]


def verify_mirror(dest_dir: Path, source: Listing, index_name: str = DEFAULT_INDEX_NAME) -> list[str]:
    """Re-hash the destination PER FILE; every divergence names its file."""

    try:
        dest = local_listing(dest_dir, index_name)
    except OSError as exc:
        return [f"cannot re-read destination {dest_dir}: {exc}"]
    mismatches: list[str] = []
    for relpath, digest in sorted(source.files.items()):
        actual = dest.files.get(relpath)
        if actual is None:
            mismatches.append(f"missing after copy: {relpath}")
        elif actual != digest:
            mismatches.append(f"hash mismatch after copy: {relpath}")
    for relpath in sorted(set(dest.files) - set(source.files)):
        mismatches.append(f"unexpected extra file after copy: {relpath}")
    return mismatches


def write_manifest(dest_dir: Path, listing: Listing) -> None:
    lines = [f"{digest}  {relpath}" for relpath, digest in sorted(listing.files.items())]
    (dest_dir / MANIFEST_NAME).write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_snapshot(dest_dir: Path, snapshot_dir: Path) -> None:
    """Copy the verified mirror to a dated snapshot; never deletes anything.

    Copied to a temp sibling and renamed on completion: a half-copied recovery point is worse
    than none, because it looks whole.
    """

    snapshot_dir.parent.mkdir(parents=True, exist_ok=True)
    if snapshot_dir.exists():
        return
    temporary = snapshot_dir.with_name(f"{snapshot_dir.name}.tmp-{os.getpid()}")
    if temporary.exists():
        shutil.rmtree(temporary)
    try:
        shutil.copytree(dest_dir, temporary)
        os.replace(temporary, snapshot_dir)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def ensure_readme(destination: Path) -> None:
    readme = destination / "README.md"
    if not readme.exists():
        readme.write_text(README_TEXT, encoding="utf-8")


def work_paths(destination: Path, dest_name: str) -> tuple[Path, Path]:
    """Staging and previous-mirror dirs, in a RESERVED namespace.

    Live mirror dirs are always ``<host>-<slug>`` and a host name never starts with a dot, so
    nothing a directory can be named collides with ``._work/``. (Putting ``<name>.previous`` next
    to the live mirrors would collide with a real directory whose slug ends in ``.previous``.)
    """

    work_dir = destination / WORK_DIRNAME
    return work_dir / f"{dest_name}.staging", work_dir / f"{dest_name}.previous"


def recover_interrupted_swap(dest_dir: Path, staging_dir: Path, previous_dir: Path) -> None:
    """Restore state left by a process killed mid-swap, BEFORE any guard runs.

    A kill between the two renames leaves only ``previous``. The next run would otherwise see no
    mirror, skip every shape guard, and could publish an emptied source over the retained copy.
    """

    if previous_dir.exists():
        if not dest_dir.exists():
            os.replace(previous_dir, dest_dir)
        else:
            shutil.rmtree(previous_dir)
    if staging_dir.exists():
        shutil.rmtree(staging_dir, ignore_errors=True)


def publish_mirror(staging_dir: Path, dest_dir: Path, previous_dir: Path) -> None:
    """Swap a verified staged copy into place, keeping the previous mirror until it is."""

    if previous_dir.exists():
        shutil.rmtree(previous_dir)
    if dest_dir.exists():
        os.replace(dest_dir, previous_dir)
    try:
        os.replace(staging_dir, dest_dir)
    except OSError:
        if previous_dir.exists() and not dest_dir.exists():
            os.replace(previous_dir, dest_dir)
        raise
    if previous_dir.exists():
        shutil.rmtree(previous_dir)


def mirror_corpus(
    corpus: Corpus,
    destination: Path,
    settings: MirrorSettings,
    today: date,
    *,
    dry_run: bool = False,
) -> CorpusOutcome:
    """Mirror one directory. With ``dry_run``, list and run the shape guard, write nothing."""

    dest_dir = destination / corpus.dest_name
    staging_dir, previous_dir = work_paths(destination, corpus.dest_name)
    current_dir = dest_dir
    if dry_run:
        # Recovery renames directories, so a dry run only reads what recovery WOULD restore.
        if previous_dir.is_dir() and not dest_dir.exists():
            current_dir = previous_dir
    else:
        recover_interrupted_swap(dest_dir, staging_dir, previous_dir)

    def cleanup(outcome: CorpusOutcome) -> CorpusOutcome:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        return outcome

    def guard(source: Listing, dest: Listing | None) -> list[str]:
        return refusal_reasons(source, dest, settings.max_deletions,
                               index_name=settings.index_name,
                               max_index_shrink=settings.max_index_shrink)

    source, error = fetch_source_listing(corpus, settings)
    if source is None:
        return CorpusOutcome(corpus, "unknown", error)

    dest: Listing | None = None
    if current_dir.is_dir():
        try:
            dest = local_listing(current_dir, settings.index_name)
        except OSError as exc:
            return CorpusOutcome(corpus, "unknown", f"cannot read mirror {current_dir}: {exc}")

    reasons = guard(source, dest)
    if reasons:
        return CorpusOutcome(corpus, "refused", "; ".join(reasons), findings={
            "guard": "shape-refusal",
            "deletions": sorted(set(dest.files) - set(source.files)) if dest else [],
            "source_files": len(source.files),
            "mirror_files": len(dest.files) if dest else 0,
        })

    if dry_run:
        deletions = sorted(set(dest.files) - set(source.files)) if dest else []
        return CorpusOutcome(corpus, "ok", "dry run: the shape guard passed; nothing was written",
                             findings={"dry_run": True, "files": len(source.files),
                                       "would_delete": deletions})

    # Copy into staging, never the live mirror. The listing above is stale the moment it is
    # fetched; if the source is wiped between that fetch and the copy, rsync --delete must not
    # get to empty the live mirror.
    try:
        if staging_dir.exists():
            shutil.rmtree(staging_dir)
        staging_dir.mkdir(parents=True)
    except OSError as exc:
        return CorpusOutcome(corpus, "unknown", f"cannot create staging dir {staging_dir}: {exc}")

    rc, _stdout, stderr = run_rsync(build_rsync_argv(corpus.host, corpus.path, staging_dir),
                                    settings.timeout)
    if rc != 0:
        return cleanup(CorpusOutcome(
            corpus, "unknown",
            f"rsync to {staging_dir} failed (rc={rc}): {stderr.strip()[:200] or 'no stderr'}",
        ))

    # Re-read the source AFTER the copy and treat THAT as the truth: verify the staged copy
    # against it, then run the shape guard again. A mid-copy wipe refuses with the previous
    # mirror intact instead of propagating.
    source, error = fetch_source_listing(corpus, settings)
    if source is None:
        return cleanup(CorpusOutcome(corpus, "unknown", error))
    mismatches = verify_mirror(staging_dir, source, settings.index_name)
    if mismatches:
        return cleanup(CorpusOutcome(
            corpus, "unknown",
            f"verification failed for {corpus.dest_name}: {'; '.join(mismatches[:5])}",
            findings={"mismatches": mismatches},
        ))
    reasons = guard(source, dest)
    if reasons:
        return cleanup(CorpusOutcome(corpus, "refused", "; ".join(reasons),
                                     findings={"guard": "shape-refusal-post-copy"}))

    try:
        publish_mirror(staging_dir, dest_dir, previous_dir)
        write_manifest(dest_dir, source)
        write_snapshot(dest_dir, destination / SNAPSHOTS_DIRNAME / corpus.dest_name / today.isoformat())
        ensure_readme(destination)
    except OSError as exc:
        return CorpusOutcome(corpus, "unknown", f"cannot publish mirror: {exc}")
    return CorpusOutcome(corpus, "ok", findings={"files": len(source.files)})


def load_state(path: Path) -> dict:
    """Load the latch record. Raises StateCorrupt rather than silently resetting it."""

    state = load_json_state(path)
    alerted = state.get("alerted", {})
    if not isinstance(alerted, dict) or not all(
        isinstance(v, (int, float)) and not isinstance(v, bool) for v in alerted.values()
    ):
        raise StateCorrupt(f"state file {path} has an invalid 'alerted' mapping")
    return state


def save_state(path: Path, state: dict) -> None:
    save_json_state(path, state)


def dedupe_key_for(host: str, kind: str, slug: str) -> str:
    """Host-keyed: identical slugs exist on different machines."""

    return f"guarded-mirror/{kind}/{host}/{slug}"


def deliver_alerts(
    outcomes: list[CorpusOutcome],
    prev_alerted: dict[str, float],
    now: float,
    reminder_seconds: float,
) -> dict[str, float]:
    alerted = dict(prev_alerted)
    for outcome in outcomes:
        if outcome.status == "ok":
            continue
        kind = outcome.status
        key = dedupe_key_for(outcome.corpus.host, kind, outcome.corpus.slug)
        last = alerted.get(key)
        if last is not None and now - last < reminder_seconds:
            continue
        if kind == "refused":
            severity = "critical"
            summary = f"guarded mirror REFUSED to update {outcome.corpus.dest_name}: {outcome.reason}"
        else:
            severity = "warn"
            summary = f"CANNOT MIRROR {outcome.corpus.dest_name}: {outcome.reason}"
        result = alert(
            severity,
            "guarded-mirror",
            summary,
            details={"host": outcome.corpus.host, "slug": outcome.corpus.slug,
                     "status": outcome.status, "reason": outcome.reason},
            dedupe_key=key,
            tags=("guarded-mirror",),
        )
        if result is not None and not result.success:
            continue
        alerted[key] = now
    return alerted


def summarize(outcomes: list[CorpusOutcome], hosts_total: int) -> tuple[int, dict]:
    unknowns = [o for o in outcomes if o.status == "unknown"]
    refused = [o for o in outcomes if o.status == "refused"]
    ok = [o for o in outcomes if o.status == "ok"]
    if unknowns:
        verdict, code = "UNKNOWN", EXIT_UNKNOWN
    elif refused:
        verdict, code = "FINDINGS", EXIT_FINDINGS
    else:
        verdict, code = "OK", EXIT_OK
    payload = {
        "status": verdict,
        "reason": "; ".join(o.reason for o in [*unknowns, *refused][:5]),
        "hosts": hosts_total,
        "directories": len(outcomes),
        "ok": [o.corpus.dest_name for o in ok],
        "refused": [{"directory": o.corpus.dest_name, "reason": o.reason} for o in refused],
        "unknown": [{"directory": o.corpus.dest_name, "reason": o.reason} for o in unknowns],
    }
    return code, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="guarded-mirror",
        description="Mirror indexed directories with a truncation guard and two-way hash "
        "verification. Exit 0 OK, 1 refused (mirror intact), 3 UNKNOWN.",
    )
    parser.add_argument("--hosts", default="localhost",
                        help="comma-separated hosts to sweep; 'localhost' is this machine")
    parser.add_argument("--destination", default=os.environ.get(DESTINATION_ENV),
                        help=f"mirror root (or set {DESTINATION_ENV}); required")
    parser.add_argument("--source-glob", default=DEFAULT_SOURCE_GLOB)
    parser.add_argument("--index-name", default=DEFAULT_INDEX_NAME,
                        help="index file whose edit legitimizes a deletion")
    parser.add_argument("--max-deletions", type=int, default=DEFAULT_MAX_DELETIONS)
    parser.add_argument("--max-index-shrink", type=int, default=DEFAULT_MAX_INDEX_SHRINK)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--state-file", default=DEFAULT_STATE_FILE)
    parser.add_argument("--reminder-seconds", type=float, default=DEFAULT_REMINDER_SECONDS)
    parser.add_argument("--date", default=None, help="override the snapshot date (YYYY-MM-DD)")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-alert", action="store_true",
                        help="mirror as usual, but send no alerts and write no state file")
    parser.add_argument("--dry-run", action="store_true",
                        help="list sources and run the shape guard only: copy nothing, write "
                        "nothing, send no alerts")
    args = parser.parse_args(argv)

    def usage_error(message: str) -> int:
        print(f"guarded-mirror: {message}", file=sys.stderr)
        return EXIT_MISCONFIGURED

    if not args.destination:
        return usage_error(f"--destination (or {DESTINATION_ENV}) is required")
    if args.max_deletions < 0 or args.max_index_shrink < 0:
        return usage_error("--max-deletions and --max-index-shrink must not be negative")
    if "/" in args.index_name or not args.index_name:
        return usage_error("--index-name must be a plain file name")
    try:
        glob = validate_glob(args.source_glob)
    except ValueError as exc:
        return usage_error(str(exc))
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    if not hosts:
        return usage_error("--hosts must name at least one host")

    settings = MirrorSettings(source_glob=glob, index_name=args.index_name,
                              max_deletions=args.max_deletions,
                              max_index_shrink=args.max_index_shrink, timeout=args.timeout)
    destination = Path(args.destination).expanduser()
    today = date.fromisoformat(args.date) if args.date else date.today()

    outcomes: list[CorpusOutcome] = []
    for host in hosts:
        corpora, error = discover_corpora(host, settings)
        placeholder = Corpus(host=host, path="", slug="discovery")
        if error:
            outcomes.append(CorpusOutcome(placeholder, "unknown", error))
            continue
        if not corpora:
            outcomes.append(CorpusOutcome(
                placeholder, "unknown",
                f"no directories matched {glob} on {host}; the source may have moved or the "
                f"host list is stale",
            ))
            continue
        for corpus in corpora:
            try:
                outcomes.append(mirror_corpus(corpus, destination, settings, today,
                                              dry_run=args.dry_run))
            except Exception as exc:  # one directory must never sink the whole run
                outcomes.append(CorpusOutcome(corpus, "unknown",
                                              f"unexpected error: {type(exc).__name__}: {exc}"))

    state_error: str | None = None
    if not (args.no_alert or args.dry_run):
        state_path = Path(args.state_file).expanduser()
        issues = [o for o in outcomes if o.status != "ok"]
        now = time.time()
        try:
            previous = load_state(state_path).get("alerted", {})
        except StateCorrupt as exc:
            # Alert anyway, unlatched, and leave the file untouched: exit 3 below.
            state_error = str(exc)
            previous = {}
        alerted = deliver_alerts(issues, previous, now, args.reminder_seconds)
        if state_error is None:
            current = {dedupe_key_for(o.corpus.host, o.status, o.corpus.slug) for o in issues}
            save_state(state_path, {"alerted": {k: v for k, v in alerted.items() if k in current},
                                    "updated_at": now})

    code, payload = summarize(outcomes, len(hosts))
    payload["dry_run"] = args.dry_run
    if state_error is not None:
        code = EXIT_UNKNOWN
        payload["status"] = "UNKNOWN"
        payload["state_error"] = state_error
        payload["reason"] = "; ".join(x for x in (state_error, payload["reason"]) if x)
    verb = "checked by the shape guard (dry run, nothing written)" if args.dry_run \
        else "mirrored and verified"
    count = len(payload["ok"])
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif payload["status"] == "OK":
        print(f"OK: {count} {'directory' if count == 1 else 'directories'} {verb} across "
              f"{len(hosts)} {'host' if len(hosts) == 1 else 'hosts'}")
    elif payload["status"] == "FINDINGS":
        names = ", ".join(r["directory"] for r in payload["refused"])
        print(f"FINDINGS: {payload['reason']} [{names}]")
    else:
        names = ", ".join(r["directory"] for r in payload["unknown"])
        print(f"UNKNOWN: {payload['reason']} [{names}]")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
