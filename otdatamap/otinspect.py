"""Read an OTInspect (ReadingDataOT) JSON report and attach its device knowledge.

OTInspect parses OT files and knows which devices they describe; OTDataMap knows
how sensitive a file is and who can read it. Feeding one into the other turns
"a restricted SCL file in the vendor folder" into "the configuration of
IED_PROT_01 (ExampleVendor EX-500, 10.20.30.11) is in the vendor folder".

The reader is deliberately forgiving: it walks the JSON and collects any object
that names a file together with device-like fields, so a change in OTInspect's
schema degrades to "no devices matched" rather than a crash.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List

PATH_KEYS = ("path", "file", "filename", "source", "source_file", "rel", "relpath")
DEVICE_KEYS = ("ied", "iedname", "ied_name", "device", "device_name", "name",
               "hostname", "controller")
VENDOR_KEYS = ("vendor", "manufacturer", "make")
MODEL_KEYS = ("model", "type", "product", "processor", "producttype")
ADDR_KEYS = ("ip", "ip_address", "address", "mgmt_ip", "management_ip")


def _first(d: Dict[str, Any], keys) -> str:
    for k in keys:
        for actual in d:
            if actual.lower().replace("-", "_") == k:
                value = d[actual]
                if isinstance(value, (str, int)) and str(value).strip():
                    return str(value).strip()
    return ""


def _norm(path: str) -> str:
    return PurePosixPath(str(path).replace("\\", "/")).name.lower()


def _walk(node: Any, current_file: str, out: Dict[str, List[dict]]) -> None:
    if isinstance(node, dict):
        file_here = ""
        for key in PATH_KEYS:
            for actual in node:
                if actual.lower() == key and isinstance(node[actual], str):
                    file_here = node[actual]
                    break
            if file_here:
                break
        scope = file_here or current_file
        name = _first(node, DEVICE_KEYS)
        vendor = _first(node, VENDOR_KEYS)
        model = _first(node, MODEL_KEYS)
        address = _first(node, ADDR_KEYS)
        if scope and name and (vendor or model or address):
            entry = {"name": name, "vendor": vendor, "model": model, "address": address}
            bucket = out[_norm(scope)]
            if entry not in bucket:
                bucket.append(entry)
        for value in node.values():
            _walk(value, scope, out)
    elif isinstance(node, list):
        for item in node:
            _walk(item, current_file, out)


def load(path: Path) -> Dict[str, List[dict]]:
    """Return {file name (lower-case): [device, ...]} from an OTInspect report."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out: Dict[str, List[dict]] = defaultdict(list)
    _walk(data, "", out)
    return dict(out)


def describe(devices: List[dict]) -> str:
    parts = []
    for d in devices[:4]:
        bits = [d["name"]]
        tail = " ".join(x for x in (d["vendor"], d["model"]) if x)
        if tail:
            bits.append(f"({tail})")
        if d["address"]:
            bits.append(d["address"])
        parts.append(" ".join(bits))
    if len(devices) > 4:
        parts.append(f"+{len(devices) - 4} more")
    return "; ".join(parts)


def attach(objects, index: Dict[str, List[dict]]) -> int:
    """Attach devices to objects whose file name OTInspect also saw."""
    matched = 0
    for obj in objects:
        name = _norm(obj.rel.split("!")[-1])
        devices = index.get(name)
        if devices:
            obj.devices = devices
            matched += 1
    return matched
