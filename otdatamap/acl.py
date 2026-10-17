"""Access control lists: who can actually read this object.

Without this, "restricted data in a shared area" is a guess based on folder
names. With it, the finding carries evidence: this object grants Read to
Everyone / Domain Users / other.

ACLs are read per directory and cached, because files normally inherit from
their parent. A file whose own permissions differ from its directory is
checked individually on POSIX (the mode is already in the stat we did).
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# Principals that mean "effectively everyone in the plant".
BROAD_PRINCIPALS = {
    "everyone", "authenticated users", "domain users", "users", "builtin\\users",
    "nt authority\\authenticated users", "nt authority\\interactive",
    "anonymous logon", "nt authority\\anonymous logon", "guests", "builtin\\guests",
    "domain computers", "network", "nt authority\\network", "other",
}

WRITE_HINTS = ("F", "M", "W", "RW", "WD", "AD", "WDAC", "WO")
READ_HINTS = ("F", "M", "RX", "R", "GR", "RD", "RE")

ICACLS_LINE = re.compile(r"^\s*(?P<principal>[^:]+?):(?P<flags>\(.*\))\s*$")


@dataclass
class AclEntry:
    principal: str
    rights: str
    can_read: bool = False
    can_write: bool = False

    @property
    def is_broad(self) -> bool:
        return self.principal.strip().lower() in BROAD_PRINCIPALS


@dataclass
class AclInfo:
    source: str = ""                       # "icacls", "getfacl", "posix", ""
    entries: List[AclEntry] = field(default_factory=list)
    error: str = ""

    @property
    def available(self) -> bool:
        return bool(self.source and not self.error)

    def broad_readers(self) -> List[AclEntry]:
        return [e for e in self.entries if e.is_broad and e.can_read]

    def broad_writers(self) -> List[AclEntry]:
        return [e for e in self.entries if e.is_broad and e.can_write]

    def describe(self) -> str:
        names = []
        for e in self.broad_writers():
            names.append(f"{e.principal} (write)")
        for e in self.broad_readers():
            if not any(e.principal == w.principal for w in self.broad_writers()):
                names.append(f"{e.principal} (read)")
        return ", ".join(names)


def _parse_icacls(output: str) -> List[AclEntry]:
    entries: List[AclEntry] = []
    first = True
    for raw in output.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if first:
            # first line starts with the path, then the first ACE after it
            parts = line.split(" ", 1)
            line = parts[1] if len(parts) > 1 else ""
            first = False
            if not line.strip():
                continue
        m = ICACLS_LINE.match(line)
        if not m:
            continue
        principal = m.group("principal").strip()
        flags = m.group("flags")
        tokens = re.findall(r"\(([^()]*)\)", flags)
        rights = ",".join(t for t in tokens if t)
        upper = [t.upper() for t in tokens]
        entries.append(AclEntry(
            principal=principal,
            rights=rights,
            can_read=any(t in READ_HINTS for t in upper),
            can_write=any(t in WRITE_HINTS for t in upper),
        ))
    return entries


def _parse_getfacl(output: str) -> List[AclEntry]:
    entries: List[AclEntry] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue
        kind, name, perms = parts[0], parts[1], parts[2]
        if kind not in ("user", "group", "other"):
            continue
        if kind == "other":
            principal = "other"
        elif not name:
            continue  # the owning user/group, covered by the mode
        else:
            principal = f"{kind}:{name}"
        entries.append(AclEntry(
            principal=principal,
            rights=perms,
            can_read="r" in perms,
            can_write="w" in perms,
        ))
    return entries


def _posix_entries(mode: int) -> List[AclEntry]:
    entries = []
    if mode & (stat.S_IROTH | stat.S_IWOTH):
        entries.append(AclEntry(
            principal="other",
            rights=("r" if mode & stat.S_IROTH else "-")
                   + ("w" if mode & stat.S_IWOTH else "-"),
            can_read=bool(mode & stat.S_IROTH),
            can_write=bool(mode & stat.S_IWOTH),
        ))
    return entries


class AclReader:
    """Reads ACLs with a per-directory cache."""

    def __init__(self, enabled: bool = True, timeout: float = 5.0) -> None:
        self.enabled = enabled
        self.timeout = timeout
        self._cache: Dict[str, AclInfo] = {}
        self._windows = sys.platform.startswith("win")
        self._icacls = shutil.which("icacls") if self._windows else None
        self._getfacl = shutil.which("getfacl") if not self._windows else None

    @property
    def backend(self) -> str:
        if not self.enabled:
            return "disabled"
        if self._icacls:
            return "icacls"
        if self._getfacl:
            return "getfacl"
        return "posix" if not self._windows else "unavailable"

    def _run(self, cmd: List[str]) -> Optional[str]:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0 and not proc.stdout:
            return None
        return proc.stdout

    def _read_path(self, path: Path) -> AclInfo:
        if self._icacls:
            out = self._run([self._icacls, str(path)])
            if out is None:
                return AclInfo(source="icacls", error="icacls failed")
            return AclInfo(source="icacls", entries=_parse_icacls(out))
        if self._getfacl:
            out = self._run([self._getfacl, "-pE", str(path)])
            if out is None:
                return AclInfo(source="getfacl", error="getfacl failed")
            return AclInfo(source="getfacl", entries=_parse_getfacl(out))
        return AclInfo(source="posix")

    def for_file(self, path: Path, mode: int = 0) -> AclInfo:
        """ACL of a file, read from its directory's cached ACL where possible."""
        if not self.enabled:
            return AclInfo()
        parent = str(path.parent)
        info = self._cache.get(parent)
        if info is None:
            info = self._read_path(path.parent)
            self._cache[parent] = info
        if info.source == "posix" or (info.source == "getfacl" and not info.entries):
            # POSIX mode is per file and we already have it from stat()
            return AclInfo(source="posix", entries=_posix_entries(mode or _mode(path)))
        if info.source == "getfacl":
            merged = list(info.entries)
            merged.extend(e for e in _posix_entries(mode or _mode(path))
                          if e.principal == "other"
                          and not any(x.principal == "other" for x in merged))
            return AclInfo(source="getfacl", entries=merged)
        return info


def _mode(path: Path) -> int:
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return 0
