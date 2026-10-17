"""Classification engine: file -> data class.

Scoring, so that a weak signal never beats a strong one:
    extension match   1 point
    file name match   2 points
    content match     3 points
Highest score wins; ties are broken by catalogue order. A COMTRADE .cfg
therefore wins over "any .cfg is a device config", because its header is
matched by content.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .util import load_yaml

DEFAULT_CATALOGUE = Path(__file__).parent / "rules" / "default_classes.yaml"

TEXTUAL_EXT = {
    ".cfg", ".conf", ".txt", ".log", ".csv", ".tsv", ".xml", ".scd", ".icd", ".cid",
    ".iid", ".ssd", ".sed", ".l5x", ".l5k", ".json", ".yaml", ".yml", ".ini", ".md",
    ".inf", ".hdr", ".xef", ".startup", ".running", ".pem", ".key", ".htpasswd", "",
}


@dataclass
class DataClass:
    id: str
    title: str
    sensitivity: str = "internal"
    impact: Dict[str, int] = field(default_factory=dict)
    retention_days: int = 0
    tags: List[str] = field(default_factory=list)
    ext: List[str] = field(default_factory=list)
    name: List[str] = field(default_factory=list)
    content: List[re.Pattern] = field(default_factory=list)

    @property
    def impact_max(self) -> int:
        return max(self.impact.values()) if self.impact else 0


@dataclass
class Catalogue:
    classes: List[DataClass]

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Catalogue":
        data = load_yaml(path or DEFAULT_CATALOGUE) or {}
        out: List[DataClass] = []
        for raw in data.get("classes", []) or []:
            match = raw.get("match") or {}
            patterns = []
            for pat in match.get("content", []) or []:
                try:
                    patterns.append(re.compile(pat, re.MULTILINE))
                except re.error:
                    continue
            out.append(
                DataClass(
                    id=str(raw["id"]),
                    title=str(raw.get("title") or raw["id"]),
                    sensitivity=str(raw.get("sensitivity") or "internal").lower(),
                    impact={k: int(v) for k, v in (raw.get("impact") or {}).items()},
                    retention_days=int(raw.get("retention_days") or 0),
                    tags=[str(t) for t in (raw.get("tags") or [])],
                    ext=[str(e).lower() for e in (match.get("ext") or [])],
                    name=[str(n).lower() for n in (match.get("name") or [])],
                    content=patterns,
                )
            )
        if not out:
            raise RuntimeError("classification catalogue is empty")
        return cls(classes=out)

    def merge(self, other: "Catalogue") -> "Catalogue":
        """User classes win over defaults with the same id, and are tried first."""
        by_id = {c.id: c for c in other.classes}
        merged = list(other.classes)
        merged += [c for c in self.classes if c.id not in by_id]
        return Catalogue(classes=merged)

    def get(self, class_id: str) -> Optional[DataClass]:
        for c in self.classes:
            if c.id == class_id:
                return c
        return None

    def classify(self, path: Path, head: str = "") -> "tuple[DataClass, str, str]":
        """Return (class, reason, confidence). Confidence says how the match was
        made: a content signature is strong evidence, an extension is a guess."""
        name = path.name.lower()
        ext = path.suffix.lower()
        best: Optional[DataClass] = None
        best_score = 0
        best_reason = ""
        for klass in self.classes:
            score, reason = 0, ""
            if ext and ext in klass.ext:
                score, reason = 1, f"extension {ext}"
            for pat in klass.name:
                if fnmatch.fnmatch(name, pat):
                    if score < 2:
                        score, reason = 2, f"file name matches {pat}"
                    break
            if head:
                for pat in klass.content:
                    if pat.search(head):
                        score, reason = 3, "content signature"
                        break
            if score > best_score:
                best, best_score, best_reason = klass, score, reason
        if best is None:
            fallback = self.get("unclassified") or self.classes[-1]
            return fallback, "no rule matched", "none"
        confidence = {3: "high", 2: "medium", 1: "low"}.get(best_score, "none")
        return best, best_reason, confidence


def is_textual(path: Path) -> bool:
    return path.suffix.lower() in TEXTUAL_EXT
