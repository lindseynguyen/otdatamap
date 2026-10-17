"""Self-contained HTML report (no external assets, works offline)."""

from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .classify import Catalogue
from .discover import DataObject
from .model import SiteModel
from .util import human_size

SEV_ORDER = ["critical", "high", "medium", "low"]

CSS = """
:root{
  --bg:#fbfbfa; --panel:#ffffff; --ink:#1f2328; --muted:#6b7280; --line:#e5e7eb;
  --accent:#2f6f8f;
  --critical:#a8323d; --high:#c2622a; --medium:#9a7b1f; --low:#4c7a63;
  --bar:#cfd8dd;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --bg:#15181c; --panel:#1c2026; --ink:#e8eaed; --muted:#9aa3ad; --line:#2b3138;
    --accent:#6fb0cf;
    --critical:#e4737f; --high:#e39a62; --medium:#d4bb63; --low:#79b79a;
    --bar:#39414a;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px} h2{font-size:18px;margin:36px 0 12px;font-weight:600}
.sub{color:var(--muted);font-size:13px;margin-bottom:28px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .n{font-size:27px;font-weight:650;letter-spacing:-.5px}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.card.critical .n{color:var(--critical)} .card.high .n{color:var(--high)}
.card.medium .n{color:var(--medium)} .card.low .n{color:var(--low)}
table{width:100%;border-collapse:collapse;background:var(--panel);
  border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:13.5px}
th{text-align:left;font-weight:600;color:var(--muted);font-size:11.5px;
  text-transform:uppercase;letter-spacing:.06em;padding:10px 12px;
  border-bottom:1px solid var(--line)}
td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:none}
td.path{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;word-break:break-all}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;
  font-size:11.5px;font-weight:600;border:1px solid currentColor}
.pill.critical{color:var(--critical)} .pill.high{color:var(--high)}
.pill.medium{color:var(--medium)} .pill.low{color:var(--low)}
.barrow{display:grid;grid-template-columns:200px 1fr 90px;gap:10px;align-items:center;
  padding:5px 0;font-size:13.5px}
.bar{height:9px;border-radius:5px;background:var(--bar)}
.bar>span{display:block;height:100%;border-radius:5px;background:var(--accent)}
.num{text-align:right;color:var(--muted);font-variant-numeric:tabular-nums;font-size:12.5px}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;
  background:var(--bar);padding:1px 5px;border-radius:4px}
.note{color:var(--muted);font-size:12.5px;margin-top:8px}
.sr{color:var(--muted);font-size:11.5px}
footer{margin-top:48px;color:var(--muted);font-size:12px;
  border-top:1px solid var(--line);padding-top:14px}
@media(max-width:640px){.barrow{grid-template-columns:120px 1fr 64px}}
"""


def _e(s) -> str:
    return html.escape(str(s))


def _devices(o) -> str:
    from .otinspect import describe
    return describe(o.devices)


def explain(obj, catalogue, rules=None) -> str:
    """Plain-text trace of why an object got the score it did."""
    klass = catalogue.get(obj.class_id) or catalogue.classes[-1]
    out = [f"{obj.rel}",
           f"  class      {klass.id} ({klass.title})",
           f"             matched by {obj.class_reason} -> {obj.confidence} confidence",
           f"  sensitivity {klass.sensitivity}, impact {klass.impact}"]
    if obj.devices:
        out.append(f"  describes  {_devices(obj)}")
    if obj.zone_id:
        out.append(f"  zone       {obj.zone_id} (owner {obj.owner or 'unnamed'})")
    if obj.acl.available:
        out.append(f"  access     {obj.acl.describe() or 'no broad principal'} "
                   f"[{obj.acl.source}]")
    if obj.signals:
        out.append("  signals    " + ", ".join(f"{s['label']} (+{s['weight']})"
                                               for s in obj.signals))
    else:
        out.append("  signals    none")
    if obj.attack:
        out.append("  enables    " + ", ".join(f"{t['id']} {t['name']}"
                                               for t in obj.attack))
    out.append(f"  risk       {obj.risk} -> {obj.severity}")
    for f in obj.findings:
        out.append(f"    [{f['severity']}] {f['id']}: {f['detail']}")
    return "\n".join(out)


def _bars(rows, total) -> str:
    out = []
    for label, count, extra in rows:
        pct = (count / total * 100) if total else 0
        out.append(
            f'<div class="barrow"><div>{_e(label)}</div>'
            f'<div class="bar"><span style="width:{pct:.1f}%"></span></div>'
            f'<div class="num">{count}'
            + (f" &middot; {_e(extra)}" if extra else "")
            + '</div></div>'
        )
    return "".join(out)


def build_summary(objects: List[DataObject], catalogue: Catalogue,
                  model: SiteModel, root: Path) -> Dict:
    sev = Counter(o.severity for o in objects)
    by_class = Counter(o.class_id for o in objects)
    bytes_by_class: Dict[str, int] = defaultdict(int)
    for o in objects:
        bytes_by_class[o.class_id] += o.size
    findings = Counter()
    for o in objects:
        for f in o.findings:
            findings[f["id"]] += 1
    restricted = sum(1 for o in objects
                     if (catalogue.get(o.class_id) or catalogue.classes[-1]).sensitivity
                     == "restricted")
    return {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "root": str(root),
        "site": model.site,
        "objects": len(objects),
        "bytes": sum(o.size for o in objects),
        "restricted_objects": restricted,
        "severity": dict(sev),
        "by_class": dict(by_class),
        "bytes_by_class": dict(bytes_by_class),
        "findings": dict(findings),
    }


def _attack_section(attack_summary: Optional[dict]) -> str:
    if not attack_summary or not attack_summary.get("techniques"):
        return ""
    by_id = {t["id"]: t for t in attack_summary["techniques"]}
    rows = []
    for tactic in attack_summary["tactics"]:
        if not tactic["techniques"]:
            continue
        first = True
        for tid in tactic["techniques"]:
            t = by_id[tid]
            label = (f"{_e(tactic['name'])}<div class='sr'>{_e(tactic['id'])}</div>"
                     if first else "")
            rows.append(
                f"<tr><td>{label}</td><td><code>{_e(t['id'])}</code></td>"
                f"<td>{_e(t['name'])}</td><td class='num'>{t['objects']}</td>"
                f"<td class='sr'>{_e(', '.join(t['because']))}</td></tr>")
            first = False
    return ("<h2>ATT&amp;CK for ICS: what this exposure enables</h2>"
            "<p class='note'>A technique is listed when exposed data pays for it &mdash; "
            "either the exposure itself (a cleartext password buys Valid Accounts) or the "
            "content once an adversary holds it (an SCD buys network enumeration). Data "
            "sitting correctly inside its zone is not counted.</p>"
            "<table><tr><th>Tactic</th><th>Technique</th><th></th>"
            "<th class='num'>Objects</th><th>Why</th></tr>"
            + "".join(rows) + "</table>")


def to_html(objects: List[DataObject], catalogue: Catalogue, rules, model: SiteModel,
            root: Path, top: int = 100, attack_summary: Optional[dict] = None) -> str:
    s = build_summary(objects, catalogue, model, root)
    ranked = sorted(objects, key=lambda o: (-o.risk, o.rel))
    flagged = [o for o in ranked if o.findings]

    cards = "".join(
        f'<div class="card {sev}"><div class="n">{s["severity"].get(sev,0)}</div>'
        f'<div class="l">{sev}</div></div>' for sev in SEV_ORDER
    )
    cards = (f'<div class="card"><div class="n">{s["objects"]}</div>'
             f'<div class="l">objects</div></div>'
             f'<div class="card"><div class="n">{human_size(s["bytes"])}</div>'
             f'<div class="l">volume</div></div>'
             f'<div class="card"><div class="n">{s["restricted_objects"]}</div>'
             f'<div class="l">restricted</div></div>' + cards)

    class_rows = []
    for cid, count in sorted(s["by_class"].items(), key=lambda kv: -kv[1]):
        klass = catalogue.get(cid)
        label = f"{klass.title if klass else cid}"
        class_rows.append((label, count, human_size(s["bytes_by_class"].get(cid, 0))))
    class_bars = _bars(class_rows, s["objects"])

    sens_rows = []
    sens_count = Counter((catalogue.get(o.class_id) or catalogue.classes[-1]).sensitivity
                         for o in objects)
    for level in ["restricted", "confidential", "internal", "public"]:
        if sens_count.get(level):
            sens_rows.append((level, sens_count[level], ""))
    sens_bars = _bars(sens_rows, s["objects"])

    frows = []
    for fid, count in sorted(s["findings"].items(), key=lambda kv: -kv[1]):
        spec = rules.findings.get(fid, {})
        frows.append(
            f"<tr><td><code>{_e(fid)}</code></td>"
            f'<td><span class="pill {_e(spec.get("severity","medium"))}">'
            f'{_e(spec.get("severity","medium"))}</span></td>'
            f"<td>{_e(spec.get('title', fid))}"
            f'<div class="sr">IEC 62443-3-3: {_e(", ".join(spec.get("sr", [])) or "-")}'
            f' &middot; ATT&CK ICS: {_e(", ".join(spec.get("attack", [])) or "-")}</div></td>'
            f"<td class='num'>{count}</td>"
            f"<td>{_e(spec.get('remediation',''))}</td></tr>"
        )
    findings_table = ("<table><tr><th>Rule</th><th>Severity</th><th>Finding</th>"
                      "<th class='num'>Count</th><th>Remediation</th></tr>"
                      + "".join(frows) + "</table>") if frows else \
        '<p class="note">No findings were raised.</p>'

    orows = []
    for o in flagged[:top]:
        klass = catalogue.get(o.class_id)
        ids = ", ".join(sorted({f["id"] for f in o.findings}))
        orows.append(
            f'<tr><td class="path">{_e(o.rel)}</td>'
            f"<td>{_e(klass.title if klass else o.class_id)}"
            f'<div class="sr">match: {_e(o.confidence)} confidence'
            + (f' &middot; {_e(_devices(o))}' if o.devices else "")
            + '</div></td>'
            f"<td>{_e(o.zone_id or '-')}</td>"
            f"<td>{_e(o.owner or '-')}</td>"
            f'<td><span class="pill {o.severity}">{o.risk}</span></td>'
            f"<td><code>{_e(ids)}</code></td></tr>"
        )
    objects_table = ("<table><tr><th>Object</th><th>Class</th><th>Zone</th><th>Owner</th>"
                     "<th>Risk</th><th>Findings</th></tr>" + "".join(orows) + "</table>") \
        if orows else '<p class="note">Nothing flagged.</p>'

    zrows = []
    if not model.empty:
        per_zone: Dict[str, List[DataObject]] = defaultdict(list)
        for o in objects:
            per_zone[o.zone_id or ""].append(o)
        for zone in model.zones:
            items = per_zone.get(zone.id, [])
            bad = sum(1 for o in items if o.findings)
            zrows.append(
                f"<tr><td>{_e(zone.name or zone.id)}</td><td>{_e(zone.max_class)}</td>"
                f"<td>{_e(zone.sl_t if zone.sl_t is not None else '-')}</td>"
                f"<td>{_e(zone.owner or '-')}</td><td class='num'>{len(items)}</td>"
                f"<td class='num'>{bad}</td></tr>"
            )
        unmapped = per_zone.get("", [])
        if unmapped:
            zrows.append(
                f"<tr><td><em>Outside every declared zone</em></td><td>-</td><td>-</td>"
                f"<td>-</td><td class='num'>{len(unmapped)}</td>"
                f"<td class='num'>{sum(1 for o in unmapped if o.findings)}</td></tr>"
            )
    zones_table = ("<h2>Zones</h2><table><tr><th>Zone</th><th>Max class</th><th>SL-T</th>"
                   "<th>Owner</th><th class='num'>Objects</th><th class='num'>Flagged</th></tr>"
                   + "".join(zrows) + "</table>") if zrows else ""

    title = f"OT data risk report{(' &ndash; ' + _e(s['site'])) if s['site'] else ''}"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>{CSS}</style></head><body><div class="wrap">
<h1>{title}</h1>
<div class="sub">{_e(s['root'])} &middot; generated {_e(s['generated'])} &middot;
OTDataMap reads files only; it never connects to a device.</div>
<div class="cards">{cards}</div>
<h2>What data is here</h2>{class_bars}
<h2>Sensitivity</h2>{sens_bars}
{zones_table}
<h2>Findings</h2>{findings_table}
{_attack_section(attack_summary)}
<h2>Flagged objects <span class="sr">(top {top} by risk)</span></h2>{objects_table}
<footer>Risk score = class sensitivity and impact (max 45) + exposure signals (max 55).
The IEC 62443-3-3 and MITRE ATT&amp;CK for ICS references are evidence pointers for an
assessor, not a compliance verdict.</footer>
</div></body></html>"""


def to_json(objects: List[DataObject], catalogue: Catalogue, model: SiteModel,
            root: Path, attack_summary: Optional[dict] = None) -> str:
    payload = {
        "tool": "otdatamap",
        "summary": build_summary(objects, catalogue, model, root),
        "attack": attack_summary or {},
        "objects": [
            {
                "path": o.rel,
                "size": o.size,
                "modified": o.mtime.isoformat(),
                "sha256": o.digest,
                "class": o.class_id,
                "class_reason": o.class_reason,
                "confidence": o.confidence,
                "devices": o.devices,
                "attack": o.attack,
                "acl": {"source": o.acl.source,
                        "broad": [e.principal for e in o.acl.broad_readers()
                                  + o.acl.broad_writers()]},
                "sensitivity": (catalogue.get(o.class_id) or catalogue.classes[-1]).sensitivity,
                "zone": o.zone_id,
                "owner": o.owner,
                "risk": o.risk,
                "severity": o.severity,
                "signals": [{"id": s["id"], "label": s["label"]} for s in o.signals],
                "findings": o.findings,
            }
            for o in sorted(objects, key=lambda x: (-x.risk, x.rel))
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_csv(objects: List[DataObject], catalogue: Catalogue) -> str:
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["path", "class", "confidence", "sensitivity", "zone", "owner",
                "size_bytes", "modified", "risk", "severity", "findings",
                "devices", "sha256"])
    for o in sorted(objects, key=lambda x: (-x.risk, x.rel)):
        klass = catalogue.get(o.class_id) or catalogue.classes[-1]
        w.writerow([o.rel, o.class_id, o.confidence, klass.sensitivity,
                    o.zone_id, o.owner, o.size,
                    o.mtime.isoformat(), o.risk, o.severity,
                    ";".join(sorted({f["id"] for f in o.findings})),
                    _devices(o), o.digest])
    return buf.getvalue()
