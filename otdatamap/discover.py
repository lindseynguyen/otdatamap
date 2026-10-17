"""Filesystem discovery.

Read-only by design: OTDataMap opens files, never writes to the scanned tree
and never connects to a device.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List

HEAD_BYTES = 256 * 1024
FULL_HASH_LIMIT = 64 * 1024 * 1024  # above this, hash head+tail+size instead

SKIP_DIRS = {".git", ".svn", "__pycache__", "node_modules", ".venv", "venv"}


@dataclass
class DataObject:
    path: Path
    rel: str
    size: int
    mtime: datetime
    mode: int = 0
    digest: str = ""
    head: str = ""
    class_id: str = ""
    class_reason: str = ""
    zone_id: str = ""
    owner: str = ""
    signals: List[Dict] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    risk: int = 0
    severity: str = "low"

    @property
    def age_days(self) -> int:
        return max(0, (datetime.now(timezone.utc) - self.mtime).days)

    @property
    def world_readable(self) -> bool:
        return bool(self.mode & stat.S_IROTH)

    @property
    def world_writable(self) -> bool:
        return bool(self.mode & stat.S_IWOTH)


def _digest(path: Path, size: int) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            if size <= FULL_HASH_LIMIT:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            else:
                h.update(fh.read(4 * 1024 * 1024))
                fh.seek(-4 * 1024 * 1024, os.SEEK_END)
                h.update(fh.read())
                h.update(str(size).encode())
    except OSError:
        return ""
    return h.hexdigest()


def _head_text(path: Path, textual: bool) -> str:
    if not textual:
        return ""
    try:
        with path.open("rb") as fh:
            raw = fh.read(HEAD_BYTES)
    except OSError:
        return ""
    if b"\x00" in raw[:2048]:
        return ""
    return raw.decode("utf-8", errors="replace")


def walk(root: Path, max_file_mb: int = 0,
         follow_symlinks: bool = False) -> Iterator[DataObject]:
    from .classify import is_textual

    root = root.resolve()
    limit = max_file_mb * 1024 * 1024 if max_file_mb else 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            try:
                if fpath.is_symlink() and not follow_symlinks:
                    continue
                st = fpath.stat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            size = st.st_size
            rel = str(fpath.relative_to(root)).replace("\\", "/")
            obj = DataObject(
                path=fpath,
                rel=rel,
                size=size,
                mtime=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
                mode=stat.S_IMODE(st.st_mode),
            )
            if limit and size > limit:
                obj.head = ""
                obj.digest = ""
            else:
                obj.head = _head_text(fpath, is_textual(fpath))
                obj.digest = _digest(fpath, size)
            yield obj
