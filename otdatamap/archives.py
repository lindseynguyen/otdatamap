"""Look inside archives without extracting them.

A contractor handover is almost always one .zip, and a Siemens TIA export is a
.zapXX — which is also a zip. Treating that as a single unclassified blob hides
exactly the data that matters, so members are listed and classified in place.

Guards: member count, total uncompressed size, compression ratio (zip bomb),
absolute and traversing member paths. Nothing is ever written to disk.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import List, Optional

ZIP_EXT = {".zip", ".jar", ".xlsx", ".docx", ".pptx"}
OT_ZIP_EXT = {".zap13", ".zap14", ".zap15", ".zap16", ".zap17", ".zap18", ".zap19",
              ".zap20", ".apa", ".gbck"}

# Office files are zips too, but their members are meaningless here.
OPENABLE = (ZIP_EXT - {".xlsx", ".docx", ".pptx", ".jar"}) | OT_ZIP_EXT

MAX_MEMBERS = 2000
MAX_TOTAL_UNCOMPRESSED = 2 * 1024 * 1024 * 1024
MAX_RATIO = 200
MEMBER_HEAD_BYTES = 256 * 1024
MEMBER_TEXT_LIMIT = 8 * 1024 * 1024


@dataclass
class ArchiveMember:
    name: str
    size: int
    mtime: datetime
    head: str = ""


@dataclass
class ArchiveResult:
    members: List[ArchiveMember]
    truncated: bool = False
    error: str = ""


def is_archive(path: Path) -> bool:
    return path.suffix.lower() in OPENABLE


def _safe_name(name: str) -> bool:
    if name.startswith("/") or name.startswith("\\") or ":" in name.split("/")[0][1:2]:
        return False
    p = PurePosixPath(name.replace("\\", "/"))
    return ".." not in p.parts


def _member_mtime(info: zipfile.ZipInfo) -> datetime:
    try:
        return datetime(*info.date_time, tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


def read_members(path: Path, read_text: bool = True,
                 max_members: int = MAX_MEMBERS) -> ArchiveResult:
    from .classify import is_textual

    members: List[ArchiveMember] = []
    truncated = False
    total = 0
    compressed = 0
    try:
        with zipfile.ZipFile(path) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            for info in infos:
                if len(members) >= max_members:
                    truncated = True
                    break
                if not _safe_name(info.filename):
                    continue
                total += info.file_size
                compressed += max(info.compress_size, 1)
                if total > MAX_TOTAL_UNCOMPRESSED:
                    return ArchiveResult(members, True, "uncompressed size limit reached")
                if compressed > 1024 * 1024 and total / compressed > MAX_RATIO:
                    return ArchiveResult(members, True, "compression ratio looks hostile")
                member = ArchiveMember(
                    name=info.filename.replace("\\", "/"),
                    size=info.file_size,
                    mtime=_member_mtime(info),
                )
                if (read_text and info.file_size <= MEMBER_TEXT_LIMIT
                        and is_textual(Path(member.name))):
                    try:
                        with zf.open(info) as fh:
                            raw = fh.read(MEMBER_HEAD_BYTES)
                        if b"\x00" not in raw[:2048]:
                            member.head = raw.decode("utf-8", errors="replace")
                    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
                        pass
                members.append(member)
            if len(infos) > len(members) and not truncated:
                truncated = len(infos) > max_members
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        return ArchiveResult(members, truncated, f"{type(exc).__name__}: {exc}")
    return ArchiveResult(members, truncated)


def expand(obj, catalogue, max_members: int = MAX_MEMBERS) -> List:
    """Return DataObjects for the members of an archive object.

    Member paths are `archive.zip!inner/path`, so every location pattern that
    matched the archive also matches its members: a restricted PLC program
    inside a zip in the vendor folder is still in the vendor folder.
    """
    from .discover import DataObject

    result = read_members(obj.path, max_members=max_members)
    out: List = []
    for m in result.members:
        child = DataObject(
            path=obj.path,
            rel=f"{obj.rel}!{m.name}",
            size=m.size,
            mtime=m.mtime,
            mode=obj.mode,
            digest="",
            head=m.head,
            acl=obj.acl,
        )
        klass, reason, confidence = catalogue.classify(Path(m.name), m.head)
        child.class_id, child.class_reason, child.confidence = klass.id, reason, confidence
        child.signals.append({"id": "archive:member", "label": "Inside an archive",
                              "weight": 1})
        out.append(child)
    if result.error:
        obj.class_reason = (obj.class_reason + f"; archive not read ({result.error})").strip("; ")
    return out


def summarise(objects: List) -> Optional[str]:
    n = sum(1 for o in objects if "!" in o.rel)
    return f"{n} objects inside archives" if n else None
