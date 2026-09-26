"""Tests for the guarded mirror.

The shape guard is the point of the tool, so every scenario runs end-to-end through main()
against real directories: a guard that has not been shown to fire is not a guard. Remote hosts
are faked at the ssh/rsync boundary; one test uses the real rsync to prove --checksum matters.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import stat
from pathlib import Path

import pytest

from honest_watchdogs import guarded_mirror as mirror

LOCAL_HOST = "hostlocal"
REMOTE_HOST = "ghost"
SNAPSHOT_DATE = "2026-09-20"
LOCAL_PROJECT = "-opt-shared-notes"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_local_corpus(home: Path, project: str = LOCAL_PROJECT) -> Path:
    corpus = home / ".claude" / "projects" / project / "memory"
    corpus.mkdir(parents=True)
    write_corpus(corpus)
    return corpus


def write_corpus(corpus: Path, names: tuple[str, ...] = ("a.md", "b.md", "c.md", "d.md", "e.md")) -> None:
    corpus.mkdir(parents=True, exist_ok=True)
    for name in names:
        (corpus / name).write_text(f"lesson {name}\n", encoding="utf-8")
    (corpus / mirror.DEFAULT_INDEX_NAME).write_text(
        "".join(f"- lesson {name}\n" for name in names), encoding="utf-8"
    )


def gnu_listing_text(corpus: Path) -> str:
    """Render a fixture corpus the way sha256sum would from its root."""
    lines = []
    for path in sorted(corpus.rglob("*")):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{digest}  ./{path.relative_to(corpus).as_posix()}")
    index_path = corpus / mirror.DEFAULT_INDEX_NAME
    if index_path.is_file():
        index = str(index_path.read_bytes().count(b"\n"))
    else:
        index = mirror._NO_INDEX
    body = "\n".join(lines)
    body = f"{body}\n" if body else ""
    return f"{mirror._FILES_BEGIN}\n{body}{mirror._INDEX_BEGIN}\n{index}\n{mirror._DONE}\n"


class FakeRemote:
    """One ssh host with a fixture corpus tree, scripted at the transport layer."""

    def __init__(self, root: Path, project: str = "-opt-remote-app") -> None:
        self.corpus = root / "projects" / project / "memory"
        write_corpus(self.corpus)
        self.corpus_path = f"/export/builder/.claude/projects/{project}/memory"

    def ssh(self, host: str, command: str, timeout: float) -> tuple[int, str, str]:
        assert host == REMOTE_HOST
        if ".claude/projects/*/memory" in command:
            return 0, f"{self.corpus_path}\n", ""
        if command.startswith(f"cd {shlex.quote(self.corpus_path)}"):
            return 0, gnu_listing_text(self.corpus), ""
        raise AssertionError(f"unexpected ssh command: {command}")

    def rsync(self, argv: list[str], timeout: float) -> tuple[int, str, str]:
        source, dest_arg = argv[-2], argv[-1]
        # The fixture stands in for rsync on every host in tests, local too.
        if source.startswith(f"{REMOTE_HOST}:"):
            src = self.corpus
        else:
            src = Path(source.rstrip("/"))
        dest = Path(dest_arg)
        dest.mkdir(parents=True, exist_ok=True)
        try:
            source_files = {p.relative_to(src).as_posix() for p in src.rglob("*") if p.is_file()}
            for existing in dest.rglob("*"):
                if existing.is_file() and existing.relative_to(dest).as_posix() not in source_files:
                    existing.unlink()
            for relpath in source_files:
                target = dest / relpath
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((src / relpath).read_bytes())
        except OSError as exc:  # a real rsync reports this shape as a non-zero rc
            return 11, "", str(exc)
        return 0, "", ""


@pytest.fixture
def fleet(tmp_path, monkeypatch):
    """A local host (real dirs, real rsync) plus a scripted remote host."""
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(mirror, "local_hostname", lambda: LOCAL_HOST)
    local_corpus = make_local_corpus(home)
    remote = FakeRemote(tmp_path / "remote-claude")
    monkeypatch.setattr(mirror, "run_ssh", remote.ssh)
    monkeypatch.setattr(mirror, "run_rsync", remote.rsync)
    return {
        "home": home,
        "local_corpus": local_corpus,
        "remote": remote,
        "destination": tmp_path / "mirror",
        "state": tmp_path / "state.json",
    }


def run_main(monkeypatch, fleet, *extra: str) -> int:
    return mirror.main([
        "--hosts", f"{LOCAL_HOST},{REMOTE_HOST}",
        "--destination", str(fleet["destination"]),
        "--state-file", str(fleet["state"]),
        "--date", SNAPSHOT_DATE,
        *extra,
    ])


def corpus_dest(fleet) -> Path:
    return fleet["destination"] / f"{LOCAL_HOST}-{mirror.slugify(LOCAL_PROJECT)}"


def test_parse_hash_lines_normalizes_sha256sum_shasum_and_bsd_forms() -> None:
    digest = "a" * 64
    text = (
        f"{digest}  ./lessons/a.md\n"
        f"{digest} *./lessons/b.md\n"
        f"SHA256 (./lessons/c.md) = {digest}\n"
    )
    assert mirror.parse_hash_lines(text) == {
        "lessons/a.md": digest,
        "lessons/b.md": digest,
        "lessons/c.md": digest,
    }


def test_parse_hash_lines_rejects_garbage_and_absolute_paths() -> None:
    with pytest.raises(ValueError):
        mirror.parse_hash_lines("not a hash line\n")
    with pytest.raises(ValueError):
        mirror.parse_hash_lines(f"{'a' * 64}  /etc/passwd\n")
    with pytest.raises(ValueError):
        mirror.parse_hash_lines(f"{'a' * 64}  ./../escape.md\n")


def test_legitimate_delete_with_index_edit_mirrors_and_snapshots(fleet, monkeypatch) -> None:
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    dest = corpus_dest(fleet)
    assert (dest / "b.md").exists()
    snapshot = (
        fleet["destination"]
        / mirror.SNAPSHOTS_DIRNAME
        / corpus_dest(fleet).name
        / SNAPSHOT_DATE
    )
    assert (snapshot / "b.md").exists()

    # Legitimate shape: ONE deletion, and MEMORY.md edited to drop its line.
    (fleet["local_corpus"] / "b.md").unlink()
    index = fleet["local_corpus"] / mirror.DEFAULT_INDEX_NAME
    index.write_text(index.read_text().replace("- lesson b.md\n", ""), encoding="utf-8")

    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    assert not (dest / "b.md").exists()
    manifest = (dest / mirror.MANIFEST_NAME).read_text()
    assert "b.md" not in manifest
    # The dated snapshot is the recovery point: --delete never touches it.
    assert (snapshot / "b.md").exists()
    assert (snapshot / mirror.DEFAULT_INDEX_NAME).read_text().count("- lesson b.md") == 1


def test_three_deletions_without_index_edit_refuses_and_keeps_mirror(fleet, monkeypatch, capsys) -> None:
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    dest = corpus_dest(fleet)

    for name in ("b.md", "c.md", "d.md"):
        (fleet["local_corpus"] / name).unlink()

    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_FINDINGS
    output = capsys.readouterr().out
    assert "deletions exceed the threshold" in output
    for name in ("b.md", "c.md", "d.md"):
        assert (dest / name).exists(), "a refused run must leave the mirror intact"
    assert "b.md" in (dest / mirror.MANIFEST_NAME).read_text()


def test_single_deletion_without_index_edit_refuses(fleet, monkeypatch) -> None:
    """Guard 2 is independent of the count threshold: even ONE deletion with
    no MEMORY.md edit is the wipe shape, not the legitimate-delete shape."""
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    dest = corpus_dest(fleet)

    (fleet["local_corpus"] / "b.md").unlink()

    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_FINDINGS
    assert (dest / "b.md").exists(), "a refused run must leave the mirror intact"


def test_memory_md_truncation_refuses(fleet, monkeypatch, capsys) -> None:
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    dest = corpus_dest(fleet)

    index = fleet["local_corpus"] / mirror.DEFAULT_INDEX_NAME
    index.write_text("- lesson a.md\n", encoding="utf-8")

    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_FINDINGS
    assert "shrank" in capsys.readouterr().out
    assert index.read_text() != (dest / mirror.DEFAULT_INDEX_NAME).read_text()
    assert (dest / mirror.DEFAULT_INDEX_NAME).read_bytes().count(b"\n") == 5


def test_memory_md_deleted_at_source_refuses(fleet, monkeypatch) -> None:
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    dest = corpus_dest(fleet)

    (fleet["local_corpus"] / mirror.DEFAULT_INDEX_NAME).unlink()
    (fleet["local_corpus"] / "b.md").unlink()

    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_FINDINGS
    assert (dest / mirror.DEFAULT_INDEX_NAME).exists()


def test_unreachable_host_is_unknown_but_other_hosts_still_mirror(fleet, monkeypatch, capsys) -> None:
    remote = fleet["remote"]

    def dead_ssh(host, command, timeout):
        return 255, "", f"ssh: connect to host {host} port 22: Operation timed out"

    def rsync_fails_only_remote(argv, timeout):
        if argv[-2].startswith(f"{REMOTE_HOST}:"):
            return -1, "", "no route to host"
        return remote.rsync(argv, timeout)

    monkeypatch.setattr(mirror, "run_ssh", dead_ssh)
    monkeypatch.setattr(mirror, "run_rsync", rsync_fails_only_remote)

    code = run_main(monkeypatch, fleet, "--no-alert")
    assert code == mirror.EXIT_UNKNOWN
    output = capsys.readouterr().out
    assert f"ssh to {REMOTE_HOST} failed" in output
    # The reachable host was mirrored anyway.
    assert corpus_dest(fleet).is_dir()
    assert (corpus_dest(fleet) / mirror.MANIFEST_NAME).exists()


def test_unwritable_destination_is_unknown_never_ok(fleet, monkeypatch, capsys) -> None:
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    dest = corpus_dest(fleet)
    before = (dest / "a.md").read_bytes()

    (fleet["local_corpus"] / "f.md").write_text("new lesson\n", encoding="utf-8")
    root = fleet["destination"]
    root.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_UNKNOWN
    finally:
        root.chmod(stat.S_IRWXU)
    output = capsys.readouterr().out
    assert "staging" in output or "publish" in output
    assert (dest / "a.md").read_bytes() == before, (
        "an unwritable destination must leave the previous mirror intact"
    )
    assert not (dest / "f.md").exists()


@pytest.mark.skipif(shutil.which("rsync") is None, reason="needs a real rsync")
def test_same_size_same_mtime_edit_still_propagates(fleet, monkeypatch) -> None:
    """rsync -a alone selects by size+mtime; --checksum must catch the edit
    that preserves both, or the mirror stays stale forever .
    Uses the real rsync for the local host: the fixture fake copies
    unconditionally and cannot model rsync's skip."""

    def real_local_rsync(argv, timeout):
        if argv[-2].startswith(f"{REMOTE_HOST}:"):
            return fleet["remote"].rsync(argv, timeout)
        import subprocess

        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, proc.stdout, proc.stderr

    monkeypatch.setattr(mirror, "run_rsync", real_local_rsync)
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    target = fleet["local_corpus"] / "a.md"
    stat_before = target.stat()
    target.write_text("lessen a.md\n", encoding="utf-8")  # same length
    os.utime(target, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))

    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    assert (corpus_dest(fleet) / "a.md").read_text(encoding="utf-8") == "lessen a.md\n"


def test_source_wipe_between_guard_and_copy_refuses_and_preserves_mirror(
    fleet, monkeypatch
) -> None:
    """TOCTOU: the pre-copy guard listing is stale the moment it is fetched.
    A source emptied between guard and rsync must refuse with the previous
    mirror intact, not propagate the wipe."""
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    dest = corpus_dest(fleet)
    remote = fleet["remote"]

    def wiping_rsync(argv, timeout):
        if not argv[-2].startswith(f"{REMOTE_HOST}:"):
            for path in fleet["local_corpus"].iterdir():
                path.unlink()
        return remote.rsync(argv, timeout)

    monkeypatch.setattr(mirror, "run_rsync", wiping_rsync)
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_FINDINGS
    assert (dest / "a.md").exists(), "mid-copy wipe must not destroy the mirror"
    assert not list((fleet["destination"] / mirror.WORK_DIRNAME).glob("*.staging")), (
        "a refused staged run must clean up its staging directory"
    )


def test_interrupted_swap_recovers_before_the_guard_runs(fleet, monkeypatch) -> None:
    """A process killed between the two publish renames leaves only
    ``._work/<name>.previous``. The next run must restore it BEFORE any
    guard runs; otherwise an emptied source sees no mirror, every guard
    passes, and the retained copy is deleted."""
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    dest = corpus_dest(fleet)
    index = fleet["local_corpus"] / mirror.DEFAULT_INDEX_NAME
    index.write_text(index.read_text() + "- lesson g.md\n", encoding="utf-8")
    (fleet["local_corpus"] / "g.md").write_text("lesson g.md\n", encoding="utf-8")

    real_replace = os.replace

    def kill_mid_swap(src, dst):
        # publish_mirror's second rename (staging -> live) kills the process;
        # RuntimeError is deliberately not the OSError publish rolls back on.
        if Path(dst).name == dest.name and Path(src).name.endswith(".staging"):
            raise RuntimeError("simulated kill between renames")
        return real_replace(src, dst)

    monkeypatch.setattr(mirror.os, "replace", kill_mid_swap)
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_UNKNOWN
    assert not dest.exists()

    # The trigger: the source empties before the next run.
    for path in fleet["local_corpus"].iterdir():
        path.unlink()
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_FINDINGS
    assert (dest / "a.md").exists(), "the recovered mirror must survive the guarded run"
    assert not (dest / "g.md").exists()


def test_work_namespace_cannot_collide_with_corpus_names(fleet, monkeypatch) -> None:
    """A sibling ``<dest>.previous`` would be a valid live mirror name
    for a corpus whose slug ends in ``.previous``, so publishing one corpus
    would delete the other's mirror. Work dirs live in a reserved ``._work``
    namespace no corpus name can reach."""
    make_local_corpus(fleet["home"], project="-opt-shared-notes.previous")
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    odd_dest = fleet["destination"] / f"{LOCAL_HOST}-opt-shared-notes.previous"
    assert odd_dest.is_dir()
    assert (odd_dest / "a.md").exists()
    work = fleet["destination"] / mirror.WORK_DIRNAME
    for leftover in work.iterdir():
        assert leftover.name.endswith((".staging", ".previous")), leftover.name
        assert not (fleet["destination"] / leftover.name).exists(), leftover.name


def test_interrupted_snapshot_is_repaired_on_next_run(fleet, monkeypatch) -> None:
    """A snapshot copy that dies mid-way must not be accepted as complete on
    the next run: temp-then-rename, retry rebuilds it."""
    calls = {"n": 0}
    real_copytree = shutil.copytree

    def flaky_copytree(src, dst, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("simulated network-share interruption")
        return real_copytree(src, dst, **kwargs)

    monkeypatch.setattr(mirror.shutil, "copytree", flaky_copytree)
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_UNKNOWN
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    snapshot = (
        fleet["destination"]
        / mirror.SNAPSHOTS_DIRNAME
        / corpus_dest(fleet).name
        / SNAPSHOT_DATE
    )
    for name in ("a.md", "b.md", "c.md", "d.md", "e.md", mirror.DEFAULT_INDEX_NAME):
        assert (snapshot / name).exists(), name
    assert not list(snapshot.parent.glob("*.tmp-*"))


def test_remote_corpus_mirrors_through_ssh_layer(fleet, monkeypatch) -> None:
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    remote_dest = fleet["destination"] / f"{REMOTE_HOST}-opt-remote-app"
    for name in ("a.md", "b.md", "c.md", "d.md", "e.md", mirror.DEFAULT_INDEX_NAME):
        assert (remote_dest / name).read_bytes() == (
            fleet["remote"].corpus / name
        ).read_bytes()
    assert (remote_dest / mirror.MANIFEST_NAME).exists()


def test_manifest_matches_destination_and_parses_back(fleet, monkeypatch) -> None:
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    dest = corpus_dest(fleet)
    manifest = mirror.parse_hash_lines((dest / mirror.MANIFEST_NAME).read_text())
    on_disk = mirror.local_listing(dest)
    assert manifest == on_disk.files
    assert mirror.MANIFEST_NAME not in on_disk.files


def test_readme_written_at_mirror_root(fleet, monkeypatch) -> None:
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    readme = fleet["destination"] / "README.md"
    assert readme.exists()
    assert "NOT" in readme.read_text()


def test_refusal_alerts_carry_host_keyed_dedupe_and_receipt(fleet, monkeypatch, tmp_path) -> None:
    """Through the real alert path: stdout sink, real receipts, real latch."""
    monkeypatch.setenv("WATCHDOG_ALERT_SINKS", "stdout")
    real_alert = mirror.alert
    calls: list[str] = []

    def recording_alert(severity, component, summary, **kwargs):
        calls.append(kwargs["dedupe_key"])
        return real_alert(severity, component, summary, **kwargs)

    monkeypatch.setattr(mirror, "alert", recording_alert)

    assert run_main(monkeypatch, fleet) == mirror.EXIT_OK
    for name in ("b.md", "c.md", "d.md"):
        (fleet["local_corpus"] / name).unlink()
    assert run_main(monkeypatch, fleet) == mirror.EXIT_FINDINGS

    assert calls, "a refusal must send an alert"
    for key in calls:
        assert key.startswith(f"guarded-mirror/refused/{LOCAL_HOST}/"), key

    receipts = sorted((tmp_path / "_receipts").glob("*-alerts.jsonl"))
    assert receipts, "the alert must leave a receipt"
    events = [json.loads(line) for line in receipts[-1].read_text().splitlines()]
    ours = [e for e in events if e["component"] == "guarded-mirror"]
    assert ours and any("REFUSED" in e["summary"] for e in ours)
    assert all(e["status"] == "delivered" and e["sink"] == "stdout" for e in ours)

    # The reminder latch suppresses an immediate re-page.
    alert_count = len(calls)
    assert run_main(monkeypatch, fleet) == mirror.EXIT_FINDINGS
    assert len(calls) == alert_count, "reminder latch must not re-page"
    state = json.loads(fleet["state"].read_text())
    assert any(key.startswith(f"guarded-mirror/refused/{LOCAL_HOST}/") for key in state["alerted"])


def test_verification_names_the_file_rsync_swore_it_copied(fleet, monkeypatch, capsys) -> None:
    """Success is measured by reading the destination, not by rsync's exit
    code: a copy that returns 0 but drops a file must be UNKNOWN, and the
    divergence must name the file."""
    remote = fleet["remote"]

    def lying_rsync(argv, timeout):
        if argv[-2].startswith(f"{REMOTE_HOST}:"):
            dest = Path(argv[-1])
            dest.mkdir(parents=True, exist_ok=True)
            for path in sorted(remote.corpus.rglob("*")):
                if path.is_file() and path.name != "e.md":
                    (dest / path.relative_to(remote.corpus)).write_bytes(path.read_bytes())
            return 0, "", ""
        return remote.rsync(argv, timeout)

    monkeypatch.setattr(mirror, "run_rsync", lying_rsync)
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_UNKNOWN
    output = capsys.readouterr().out
    assert "e.md" in output


def test_empty_source_with_existing_mirror_refuses(fleet, monkeypatch) -> None:
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    dest = corpus_dest(fleet)
    for path in fleet["local_corpus"].iterdir():
        path.unlink()
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_FINDINGS
    assert (dest / "a.md").exists()


# --- configuration -----------------------------------------------------------------------------


def test_slug_follows_the_wildcard_components_of_the_glob() -> None:
    assert mirror.corpus_slug("/x/y/.claude/projects/-opt-app/memory") == "opt-app"
    assert mirror.corpus_slug("/srv/exports/team-a/notes", "/srv/exports/*/notes") == "team-a"
    assert mirror.corpus_slug("/srv/a/b/c", "/srv/*/b/*") == "a-c"
    assert mirror.corpus_slug("/srv/fixed", "/srv/fixed") == "fixed"


def test_unsafe_globs_are_refused() -> None:
    for bad in ("relative/*", "~/x/$(rm -rf ~)", "/a/../b/*", "/a b/*"):
        with pytest.raises(ValueError):
            mirror.validate_glob(bad)
    assert mirror.validate_glob("~/notes/*/index") == "~/notes/*/index"


def test_destination_is_required(capsys) -> None:
    assert mirror.main(["--hosts", "localhost"]) == 2
    assert "--destination" in capsys.readouterr().err


def test_a_custom_glob_and_index_name_are_honoured(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(mirror, "local_hostname", lambda: LOCAL_HOST)
    source = tmp_path / "src" / "team-a" / "notes"
    source.mkdir(parents=True)
    (source / "one.txt").write_text("1\n")
    (source / "INDEX").write_text("- one\n")
    code = mirror.main([
        "--hosts", "localhost", "--destination", str(tmp_path / "dest"),
        "--source-glob", f"{tmp_path}/src/*/notes", "--index-name", "INDEX",
        "--state-file", str(tmp_path / "state.json"), "--no-alert",
    ])
    assert code == mirror.EXIT_OK
    assert (tmp_path / "dest" / "localhost-team-a" / "one.txt").read_text() == "1\n"


def test_no_matching_directories_is_unknown_not_ok(tmp_path, capsys) -> None:
    code = mirror.main([
        "--hosts", "localhost", "--destination", str(tmp_path / "dest"),
        "--source-glob", f"{tmp_path}/nothing/*/here", "--no-alert",
    ])
    assert code == mirror.EXIT_UNKNOWN
    assert "no directories matched" in capsys.readouterr().out


# --- dry run, and the state file ---------------------------------------------------------------


def _tree(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()} if root.exists() else {}


def test_dry_run_writes_nothing_at_all(fleet, monkeypatch, capsys) -> None:
    code = run_main(monkeypatch, fleet, "--dry-run")
    assert code == mirror.EXIT_OK
    assert not fleet["destination"].exists(), "a dry run created the destination"
    assert not fleet["state"].exists(), "a dry run wrote the state file"
    assert "dry run, nothing written" in capsys.readouterr().out


def test_dry_run_leaves_an_existing_mirror_byte_for_byte(fleet, monkeypatch) -> None:
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    before = _tree(fleet["destination"])
    (fleet["local_corpus"] / "new.md").write_text("new lesson\n")
    assert run_main(monkeypatch, fleet, "--dry-run") == mirror.EXIT_OK
    assert _tree(fleet["destination"]) == before


def test_dry_run_still_reports_a_refusal(fleet, monkeypatch) -> None:
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    for name in ("b.md", "c.md", "d.md"):
        (fleet["local_corpus"] / name).unlink()
    assert run_main(monkeypatch, fleet, "--dry-run") == mirror.EXIT_FINDINGS


def test_the_ok_line_pluralizes_correctly(fleet, monkeypatch, capsys) -> None:
    assert run_main(monkeypatch, fleet, "--no-alert") == mirror.EXIT_OK
    assert "OK: 2 directories mirrored and verified across 2 hosts" in capsys.readouterr().out


@pytest.mark.parametrize("content", ["{not json", "[]", '{"alerted": ["x"]}'])
def test_a_corrupt_state_file_is_unknown_and_left_untouched(fleet, monkeypatch, content) -> None:
    """MUST-FIRE: a clean mirror run over a broken latch record is exit 3, not 0."""
    fleet["state"].write_text(content)
    assert run_main(monkeypatch, fleet) == mirror.EXIT_UNKNOWN
    assert fleet["state"].read_text() == content
