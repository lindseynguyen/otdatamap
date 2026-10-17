"""Site model: zones, stores and owners.

The model is optional. Without it OTDataMap still classifies and scores every
object; with it, objects can be checked against the zone they sit in
(IEC 62443-3-2 style) and attributed to an owner.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .util import load_yaml

SENSITIVITY_ORDER = ["public", "internal", "confidential", "restricted"]


def sensitivity_rank(value: str) -> int:
    try:
        return SENSITIVITY_ORDER.index((value or "internal").lower())
    except ValueError:
        return 1


@dataclass
class Zone:
    id: str
    name: str = ""
    sl_t: Optional[int] = None
    max_class: str = "restricted"
    owner: str = ""
    description: str = ""
    paths: List[str] = field(default_factory=list)

    def matches(self, rel_path: str) -> bool:
        p = rel_path.replace("\\", "/").lower()
        return any(fnmatch.fnmatch(p, pat.lower().rstrip("/") + "/*")
                   or fnmatch.fnmatch(p, pat.lower())
                   for pat in self.paths)


@dataclass
class SiteModel:
    site: str = ""
    zones: List[Zone] = field(default_factory=list)
    declared_paths: List[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "SiteModel":
        data: Dict[str, Any] = load_yaml(path) or {}
        zones = []
        for z in data.get("zones", []) or []:
            zones.append(
                Zone(
                    id=str(z.get("id") or z.get("name") or "zone"),
                    name=str(z.get("name") or z.get("id") or ""),
                    sl_t=z.get("sl_t"),
                    max_class=str(z.get("max_class") or "restricted"),
                    owner=str(z.get("owner") or ""),
                    description=str(z.get("description") or ""),
                    paths=[str(p) for p in (z.get("paths") or [])],
                )
            )
        declared = []
        for z in zones:
            declared.extend(z.paths)
        return cls(site=str(data.get("site") or ""), zones=zones, declared_paths=declared)

    @property
    def empty(self) -> bool:
        return not self.zones

    def zone_for(self, rel_path: str) -> Optional[Zone]:
        best: Optional[Zone] = None
        best_len = -1
        for zone in self.zones:
            for pat in zone.paths:
                p = rel_path.replace("\\", "/").lower()
                pat_l = pat.lower().rstrip("/")
                if (fnmatch.fnmatch(p, pat_l) or fnmatch.fnmatch(p, pat_l + "/*")) \
                        and len(pat_l) > best_len:
                    best, best_len = zone, len(pat_l)
        return best


TEMPLATE = """# OTDataMap site model
#
# Describe where OT data is allowed to live. Paths are relative to the folder
# you scan, and use / as separator. Everything here is optional, but a model
# turns "this file looks sensitive" into "this file is in the wrong zone".

site: Example Plant

zones:
  - id: level1-control
    name: Process control zone (Purdue level 1-2)
    sl_t: 3
    max_class: restricted
    owner: Control Systems Engineering
    description: Engineering workstations, HMI and controller projects.
    paths:
      - engineering
      - plc
      - substation_backup

  - id: level3-operations
    name: Operations zone (Purdue level 3)
    sl_t: 2
    max_class: confidential
    owner: Plant IT
    description: Historian, reporting and operations file shares.
    paths:
      - historian
      - reports

  - id: dmz
    name: IT/OT DMZ
    sl_t: 2
    max_class: internal
    owner: Plant IT
    description: Exchange area with the corporate network. No restricted data.
    paths:
      - dmz
      - transfer

  - id: vendor
    name: Vendor exchange
    sl_t: 1
    max_class: internal
    owner: Procurement
    description: Anything a contractor can read or write.
    paths:
      - vendor
      - contractor
"""
