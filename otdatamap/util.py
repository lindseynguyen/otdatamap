"""Small shared helpers (no third-party dependency except PyYAML)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:  # PyYAML is a hard dependency for rules, but keep a JSON fallback usable.
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore


def load_yaml(path: Path) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    if yaml is not None:
        return yaml.safe_load(text)
    if str(path).endswith(".json"):
        return json.loads(text)
    raise RuntimeError(
        "PyYAML is required to read %s. Install it with: pip install PyYAML" % path
    )


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024 or unit == "TB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"
