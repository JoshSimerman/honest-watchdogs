"""Small JSON state files for the instruments' re-alert latches.

A missing state file is a fresh start. A state file that exists but cannot be read or parsed is
NOT: silently replacing it with ``{}`` would reset every latch and every reminder clock, and the
instrument would report a clean run over a broken record. So it raises :class:`StateCorrupt`,
the instrument exits 3 (UNKNOWN), and the file is left untouched for a human to inspect.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


class StateCorrupt(Exception):
    """The state file exists but is unreadable, invalid JSON, or not a JSON object."""


def load_json_state(path: Path) -> dict:
    path = Path(path).expanduser()
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise StateCorrupt(f"cannot read state file {path}: {exc}") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StateCorrupt(f"state file {path} is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise StateCorrupt(f"state file {path} must contain a JSON object")
    return value


def save_json_state(path: Path, state: dict) -> None:
    """Atomically replace the state file (temp file in the same directory, then rename)."""

    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
