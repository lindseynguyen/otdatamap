"""Exposure signals, risk scoring and findings."""

from __future__ import annotations

import fnmatch
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .classify import Catalogue, DataClass
from .discover import DataObject
from .model import SiteModel, sensitivity_rank
from .util import load_yaml

DEFAULT_EXPOSURE = Path(__file__).parent / "rules" / "default_exposure.yaml"

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


@dataclass
class RuleSet:
    locations: Dict[str, dict]
    secrets: List[dict]
    thresholds: Dict[str, int]
    bands: Dict[str, int]
    findings: Dict[str, dict]

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "RuleSet":
        data = load_yaml(path or DEFAULT_EXPOSURE) or {}
        secrets = []
        for s in data.get("secrets", []) or []:
            try:
                secrets.append({**s, "re": re.compile(s["pattern"], re.MULTILINE)})
            except (re.error, KeyError):
                continue
        return cls(
            locations=data.get("locations", {}) or {},
            secrets=secrets,
            thresholds=data.get("thresholds", {}) or {},
            bands=data.get("severity_bands", {}) or {},
            findings={f["id"]: f for f in (data.get("findings", []) or [])},
        )


def _location_signals(rel: str, rules: RuleSet) -> List[Dict]:
    p = "/" + rel.lower()
    out = []
    for key, spec in rules.locations.items():
        for pat in spec.get("patterns", []):
            if fnmatch.fnmatch(p, pat.lower()):
                out.append({
                    "id": f"location:{key}",
                    "label": spec.get("label", key),
                    "weight": int(spec.get("weight", 1)),
                })
                break
    return out


def _secret_signals(head: str, rules: RuleSet) -> List[Dict]:
    out = []
    if not head:
        return out
    for spec in rules.secrets:
        if spec["re"].search(head):
            out.append({"id": f"secret:{spec['id']}", "label": spec["label"], "weight": 5})
    return out


def _finding(rules: RuleSet, fid: str, detail: str) -> Dict:
    spec = rules.findings.get(fid, {})
    return {
        "id": fid,
        "title": spec.get("title", fid),
        "severity": spec.get("severity", "medium"),
        "detail": detail,
        "sr": spec.get("sr", []),
        "attack": spec.get("attack", []),
        "remediation": spec.get("remediation", ""),
    }


def assess(objects: List[DataObject], catalogue: Catalogue, rules: RuleSet,
           model: SiteModel) -> None:
    """Annotate every object in place with zone, signals, findings and risk."""
    by_digest: Dict[str, List[DataObject]] = defaultdict(list)
    for obj in objects:
        if obj.digest:
            by_digest[obj.digest].append(obj)

    dup_threshold = int(rules.thresholds.get("duplicate_locations", 3))
    stale_days = int(rules.thresholds.get("stale_days", 540))

    declared = [d.lower().rstrip("/") for d in model.declared_paths]

    for obj in objects:
        klass: DataClass = catalogue.get(obj.class_id) or catalogue.classes[-1]
        rank = sensitivity_rank(klass.sensitivity)
        zone = model.zone_for(obj.rel)
        if zone:
            obj.zone_id, obj.owner = zone.id, zone.owner

        signals = _location_signals(obj.rel, rules) + _secret_signals(obj.head, rules)
        findings: List[Dict] = []

        for sig in signals:
            if sig["id"].startswith("secret:"):
                findings.append(_finding(rules, "DATA-SECRET-CLEARTEXT", sig["label"]))

        loc_ids = {s["id"] for s in signals}
        if rank >= 3:  # restricted
            if loc_ids & {"location:shared", "location:vendor", "location:personal"}:
                where = ", ".join(s["label"] for s in signals if s["id"] in loc_ids
                                  and s["id"].startswith("location:"))
                findings.append(_finding(rules, "DATA-RESTRICTED-IN-SHARED", where))
            if loc_ids & {"location:cloud", "location:removable"}:
                where = ", ".join(s["label"] for s in signals
                                  if s["id"] in {"location:cloud", "location:removable"})
                findings.append(_finding(rules, "DATA-RESTRICTED-EGRESS", where))
            # On POSIX almost everything is o+r, so that alone is not a finding:
            # world-WRITABLE always is, and world-readable only in an exposed area.
            exposed = bool(loc_ids & {"location:shared", "location:vendor",
                                      "location:cloud", "location:removable"})
            if obj.world_writable or (obj.world_readable and exposed):
                signals.append({"id": "perm:world", "label": "Weak file permissions",
                                "weight": 3})
                findings.append(_finding(
                    rules, "DATA-WORLD-READABLE",
                    f"mode {obj.mode:o}" + (" (world writable)" if obj.world_writable else "")))

        if zone and rank > sensitivity_rank(zone.max_class):
            signals.append({"id": "zone:violation", "label": "Above zone class", "weight": 4})
            findings.append(_finding(
                rules, "DATA-OUTSIDE-ZONE",
                f"{klass.sensitivity} data in zone '{zone.id}' (max {zone.max_class})"))
        if zone and rank >= 2 and not zone.owner:
            findings.append(_finding(rules, "DATA-NO-OWNER", f"zone '{zone.id}'"))
        if not model.empty and zone is None and rank >= 3:
            parent = obj.rel.rsplit("/", 1)[0] if "/" in obj.rel else "."
            if not any(parent.lower().startswith(d) for d in declared):
                signals.append({"id": "zone:undeclared", "label": "Undeclared store", "weight": 2})
                findings.append(_finding(rules, "DATA-UNDECLARED-STORE", parent))

        if rank >= 2 and obj.digest:
            folders = {o.rel.rsplit("/", 1)[0] if "/" in o.rel else "."
                       for o in by_digest.get(obj.digest, [])}
            if len(folders) >= dup_threshold:
                signals.append({"id": "sprawl:duplicate", "label": "Copied across folders",
                                "weight": 2})
                findings.append(_finding(rules, "DATA-SPRAWL-DUPLICATE",
                                         f"{len(folders)} folders hold this exact content"))

        if klass.retention_days and obj.age_days > klass.retention_days:
            signals.append({"id": "retention:exceeded", "label": "Past retention", "weight": 1})
            findings.append(_finding(
                rules, "DATA-RETENTION-EXCEEDED",
                f"{obj.age_days} days old, retention {klass.retention_days} days"))

        if rank >= 3 and obj.age_days > stale_days and "backup" in klass.tags + [klass.id]:
            signals.append({"id": "stale", "label": "Not refreshed", "weight": 1})
            findings.append(_finding(rules, "DATA-STALE", f"last change {obj.age_days} days ago"))

        base = (rank * 2 + klass.impact_max * 2) / 14.0 * 45.0
        exposure = min(sum(s["weight"] for s in signals), 11) / 11.0 * 55.0
        obj.signals = signals
        obj.findings = findings
        obj.risk = int(round(min(100.0, base + exposure)))
        obj.severity = severity_for(obj.risk, rules)
        for f in findings:  # a finding never scores below its own severity band
            if SEVERITY_ORDER.index(f["severity"]) > SEVERITY_ORDER.index(obj.severity):
                obj.severity = f["severity"]


def severity_for(score: int, rules: RuleSet) -> str:
    if score >= int(rules.bands.get("critical", 85)):
        return "critical"
    if score >= int(rules.bands.get("high", 65)):
        return "high"
    if score >= int(rules.bands.get("medium", 40)):
        return "medium"
    return "low"
