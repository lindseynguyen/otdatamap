"""MITRE ATT&CK for ICS: turn exposed data into the attack steps it pays for.

Two sources feed a technique onto an object:

  * the finding - what the exposure itself buys (a cleartext password buys
    Valid Accounts whatever file it sits in);
  * the data class - what the content buys once an adversary holds it (an SCD
    buys network enumeration and a credible spoofed publisher).

Class techniques only count when the object is actually exposed, i.e. it has
at least one finding. Data sitting correctly inside its zone is not an
adversary capability, it is the plant working as designed.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .util import load_yaml

DEFAULT_ATTACK = Path(__file__).parent / "rules" / "attack_ics.yaml"


@dataclass
class Technique:
    id: str
    name: str
    tactics: List[str] = field(default_factory=list)


@dataclass
class AttackMap:
    matrix: str = "ics-attack"
    tactics: List[dict] = field(default_factory=list)
    techniques: Dict[str, Technique] = field(default_factory=dict)
    class_enables: Dict[str, dict] = field(default_factory=dict)
    finding_techniques: Dict[str, List[str]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "AttackMap":
        data = load_yaml(path or DEFAULT_ATTACK) or {}
        techniques = {
            str(tid): Technique(id=str(tid), name=str(spec.get("name") or tid),
                                tactics=[str(t) for t in (spec.get("tactics") or [])])
            for tid, spec in (data.get("techniques") or {}).items()
        }
        return cls(
            matrix=str(data.get("matrix") or "ics-attack"),
            tactics=[dict(t) for t in (data.get("tactics") or [])],
            techniques=techniques,
            class_enables={str(k): dict(v) for k, v in
                           (data.get("class_enables") or {}).items()},
            finding_techniques={str(k): [str(x) for x in v] for k, v in
                                (data.get("finding_techniques") or {}).items()},
        )

    def tactic_name(self, tactic_id: str) -> str:
        for t in self.tactics:
            if t.get("id") == tactic_id:
                return str(t.get("name") or tactic_id)
        return tactic_id

    def unknown_references(self) -> List[str]:
        """Technique ids referenced by the mapping but missing from the catalogue."""
        referenced = set()
        for spec in self.class_enables.values():
            referenced.update(spec.get("techniques") or [])
        for ids in self.finding_techniques.values():
            referenced.update(ids)
        return sorted(str(r) for r in referenced if str(r) not in self.techniques)

    # ------------------------------------------------------------- annotation
    def for_object(self, obj) -> List[dict]:
        """Techniques this object enables, with the reason each one applies."""
        hits: Dict[str, set] = defaultdict(set)
        for f in obj.findings:
            for tid in self.finding_techniques.get(f["id"], []):
                hits[str(tid)].add(f["id"])
        if obj.findings:  # only exposed data is an adversary capability
            spec = self.class_enables.get(obj.class_id) or {}
            for tid in spec.get("techniques", []):
                hits[str(tid)].add(f"class:{obj.class_id}")
        out = []
        for tid, reasons in hits.items():
            tech = self.techniques.get(tid)
            if tech is None:
                continue
            out.append({
                "id": tech.id,
                "name": tech.name,
                "tactics": tech.tactics,
                "because": sorted(reasons),
            })
        return sorted(out, key=lambda t: t["id"])

    def annotate(self, objects) -> None:
        for obj in objects:
            obj.attack = self.for_object(obj)


def apply_to_rules(amap: "AttackMap", rules) -> None:
    """Make attack_ics.yaml the single source of truth for finding techniques."""
    for fid, spec in rules.findings.items():
        ids = amap.finding_techniques.get(fid)
        if ids is not None:
            spec["attack"] = list(ids)


# ------------------------------------------------------------------ aggregate
def aggregate(objects, amap: AttackMap) -> dict:
    """Counts per technique and per tactic, with example objects."""
    per_tech: Dict[str, dict] = {}
    for obj in objects:
        for tech in getattr(obj, "attack", []) or []:
            entry = per_tech.setdefault(tech["id"], {
                "id": tech["id"], "name": tech["name"], "tactics": tech["tactics"],
                "objects": 0, "examples": [], "because": set(),
            })
            entry["objects"] += 1
            entry["because"].update(tech["because"])
            if len(entry["examples"]) < 3:
                entry["examples"].append(obj.rel)
    for entry in per_tech.values():
        entry["because"] = sorted(entry["because"])

    per_tactic: Dict[str, dict] = {}
    for t in amap.tactics:
        per_tactic[t["id"]] = {"id": t["id"], "name": t["name"],
                               "techniques": [], "objects": 0}
    for entry in per_tech.values():
        for tactic_id in entry["tactics"]:
            bucket = per_tactic.setdefault(
                tactic_id, {"id": tactic_id, "name": amap.tactic_name(tactic_id),
                            "techniques": [], "objects": 0})
            bucket["techniques"].append(entry["id"])
            bucket["objects"] += entry["objects"]
    for bucket in per_tactic.values():
        bucket["techniques"] = sorted(set(bucket["techniques"]))
    return {
        "matrix": amap.matrix,
        "techniques": sorted(per_tech.values(), key=lambda e: -e["objects"]),
        "tactics": [per_tactic[t["id"]] for t in amap.tactics if t["id"] in per_tactic],
    }


def navigator_layer(summary: dict, name: str = "OTDataMap exposure") -> dict:
    """An ATT&CK Navigator layer, so the result can be opened in the matrix."""
    techniques = summary.get("techniques", [])
    top = max((t["objects"] for t in techniques), default=1)
    return {
        "name": name,
        "versions": {"layer": "4.5", "navigator": "4.9.0"},
        "domain": summary.get("matrix", "ics-attack"),
        "description": "Techniques enabled by exposed OT data, scored by the "
                       "number of exposed objects that enable each one.",
        "sorting": 3,
        "hideDisabled": True,
        "techniques": [
            {
                "techniqueID": t["id"],
                "score": t["objects"],
                "comment": "; ".join(t["because"]) + "\n" + "\n".join(t["examples"]),
                "enabled": True,
            }
            for t in techniques
        ],
        "gradient": {"colors": ["#f6f7f8", "#c2622a", "#a8323d"],
                     "minValue": 0, "maxValue": top},
        "legendItems": [],
        "metadata": [{"name": "tool", "value": "otdatamap"}],
    }


def text_matrix(summary: dict) -> str:
    lines = []
    for tactic in summary.get("tactics", []):
        if not tactic["techniques"]:
            continue
        lines.append(f"{tactic['name']} ({tactic['id']})")
        by_id = {t["id"]: t for t in summary["techniques"]}
        for tid in tactic["techniques"]:
            t = by_id[tid]
            lines.append(f"    {t['id']:<12} {t['name']:<46} {t['objects']:>4} objects")
    return "\n".join(lines) if lines else "No exposed data, so no techniques enabled."
