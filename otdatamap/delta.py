"""Compare two runs.

A single scan says "47 objects are restricted", which shocks a room once and is
then ignored. A delta says "three restricted files appeared in the vendor folder
this week", which is actionable and is the reason anyone runs the tool twice.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass
class Delta:
    baseline_generated: str = ""
    new_objects: List[dict] = field(default_factory=list)
    removed_objects: List[dict] = field(default_factory=list)
    new_findings: List[Tuple[str, str, str]] = field(default_factory=list)
    resolved_findings: List[Tuple[str, str, str]] = field(default_factory=list)
    risk_increased: List[Tuple[str, int, int]] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.new_objects or self.removed_objects or self.new_findings
                    or self.resolved_findings or self.risk_increased)

    def as_dict(self) -> dict:
        return {
            "baseline_generated": self.baseline_generated,
            "new_objects": [o["path"] for o in self.new_objects],
            "removed_objects": [o["path"] for o in self.removed_objects],
            "new_findings": [{"path": p, "finding": f, "severity": s}
                             for p, f, s in self.new_findings],
            "resolved_findings": [{"path": p, "finding": f, "severity": s}
                                  for p, f, s in self.resolved_findings],
            "risk_increased": [{"path": p, "from": a, "to": b}
                               for p, a, b in self.risk_increased],
        }


def load_run(path: Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if "objects" not in data:
        raise ValueError(f"{path} is not an OTDataMap JSON run (no 'objects' key)")
    return data


def _index(payload: dict) -> Dict[str, dict]:
    return {o["path"]: o for o in payload.get("objects", [])}


def _findings(obj: dict) -> Dict[str, str]:
    return {f["id"]: f.get("severity", "medium") for f in obj.get("findings", [])}


def compare(baseline: dict, current: dict) -> Delta:
    old, new = _index(baseline), _index(current)
    delta = Delta(baseline_generated=baseline.get("summary", {}).get("generated", ""))

    for path, obj in new.items():
        if path not in old:
            delta.new_objects.append(obj)
            for fid, sev in _findings(obj).items():
                delta.new_findings.append((path, fid, sev))
            continue
        before, after = _findings(old[path]), _findings(obj)
        for fid, sev in after.items():
            if fid not in before:
                delta.new_findings.append((path, fid, sev))
        for fid, sev in before.items():
            if fid not in after:
                delta.resolved_findings.append((path, fid, sev))
        old_risk, new_risk = old[path].get("risk", 0), obj.get("risk", 0)
        if new_risk > old_risk:
            delta.risk_increased.append((path, old_risk, new_risk))

    for path, obj in old.items():
        if path not in new:
            delta.removed_objects.append(obj)
            for fid, sev in _findings(obj).items():
                delta.resolved_findings.append((path, fid, sev))

    for bucket in (delta.new_findings, delta.resolved_findings):
        bucket.sort(key=lambda t: (t[0], t[1]))
    delta.risk_increased.sort(key=lambda t: t[1] - t[2])
    return delta


def text_summary(delta: Delta) -> str:
    if delta.empty:
        return "No change since the baseline."
    lines = []
    if delta.baseline_generated:
        lines.append(f"since {delta.baseline_generated}")
    lines.append(f"  {len(delta.new_objects):4d}  new objects")
    lines.append(f"  {len(delta.new_findings):4d}  new findings")
    lines.append(f"  {len(delta.resolved_findings):4d}  resolved findings")
    lines.append(f"  {len(delta.risk_increased):4d}  objects whose risk went up")
    worst = [t for t in delta.new_findings if t[2] in ("critical", "high")][:10]
    if worst:
        lines.append("\nnew high or critical findings:")
        lines.extend(f"  [{sev}] {fid}  {path}" for path, fid, sev in worst)
    return "\n".join(lines)
