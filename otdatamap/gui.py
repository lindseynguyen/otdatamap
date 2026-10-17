"""Desktop interface (PyQt5).

A thin shell over the same engine the CLI uses: scanning, classification,
ACLs and scoring all happen in the modules below, so the window can never
disagree with the command line.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import List, Optional

try:
    from PyQt5.QtCore import (
        QAbstractTableModel,
        QModelIndex,
        QObject,
        QSortFilterProxyModel,
        Qt,
        QThread,
        pyqtSignal,
    )
    from PyQt5.QtGui import QColor, QFont, QPalette
    from PyQt5.QtWidgets import (
        QAbstractItemView,
        QApplication,
        QCheckBox,
        QDialog,
        QFileDialog,
        QFrame,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QSplitter,
        QTableView,
        QTextBrowser,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "The GUI needs PyQt5:\n"
        '    pip install "otdatamap[gui]"\n'
        f"({exc})"
    ) from exc

from . import __version__
from .acl import AclReader
from .archives import expand, is_archive
from .attack import AttackMap, aggregate, apply_to_rules
from .classify import Catalogue
from .discover import DataObject, walk
from .learn import Syllabus, attacker_note
from .model import SiteModel
from .report import build_summary, to_csv, to_html, to_json
from .risk import RuleSet, assess
from .util import human_size

SEVERITIES = ["critical", "high", "medium", "low"]

LIGHT = {
    "bg": "#f6f7f8", "panel": "#ffffff", "ink": "#1f2328", "muted": "#6b7280",
    "line": "#e2e5e9", "accent": "#2f6f8f", "field": "#ffffff", "row": "#f2f5f7",
    "critical": "#a8323d", "high": "#c2622a", "medium": "#8a6e1c", "low": "#3f6f5b",
}
DARK = {
    "bg": "#15181c", "panel": "#1c2026", "ink": "#e8eaed", "muted": "#9aa3ad",
    "line": "#2b3138", "accent": "#6fb0cf", "field": "#20252b", "row": "#232931",
    "critical": "#e4737f", "high": "#e39a62", "medium": "#d4bb63", "low": "#79b79a",
}

QSS = """
QWidget {{ background: {bg}; color: {ink}; font-size: 13px; }}
QLabel#h1 {{ font-size: 19px; font-weight: 600; }}
QLabel#sub {{ color: {muted}; font-size: 12px; }}
QFrame#card {{ background: {panel}; border: 1px solid {line}; border-radius: 10px; }}
QLabel#cardValue {{ font-size: 22px; font-weight: 600; }}
QLabel#cardLabel {{ color: {muted}; font-size: 10px; letter-spacing: 1px; }}
QLineEdit {{ background: {field}; border: 1px solid {line}; border-radius: 7px;
             padding: 6px 9px; selection-background-color: {accent}; }}
QLineEdit:focus {{ border: 1px solid {accent}; }}
QPushButton {{ background: {panel}; border: 1px solid {line}; border-radius: 7px;
               padding: 6px 13px; }}
QPushButton:hover {{ border: 1px solid {accent}; }}
QPushButton:disabled {{ color: {muted}; }}
QPushButton#primary {{ background: {accent}; color: #ffffff; border: none;
                       padding: 7px 20px; font-weight: 600; }}
QPushButton#primary:disabled {{ background: {line}; color: {muted}; }}
QPushButton#chip {{ border-radius: 12px; padding: 4px 13px; color: {muted}; }}
QPushButton#chip:checked {{ background: {accent}; color: #ffffff; border: none; }}
QTableView {{ background: {panel}; border: 1px solid {line}; border-radius: 10px;
              gridline-color: {line}; alternate-background-color: {row};
              selection-background-color: {accent}; selection-color: #ffffff; }}
QHeaderView::section {{ background: {panel}; color: {muted}; border: none;
                        border-bottom: 1px solid {line}; padding: 7px;
                        font-size: 11px; font-weight: 600; }}
QTextBrowser {{ background: {panel}; border: 1px solid {line}; border-radius: 10px;
                padding: 8px; }}
QProgressBar {{ background: {line}; border: none; border-radius: 3px; max-height: 6px; }}
QProgressBar::chunk {{ background: {accent}; border-radius: 3px; }}
QCheckBox {{ color: {muted}; }}
QSplitter::handle {{ background: transparent; height: 8px; }}
"""


def palette_is_dark() -> bool:
    app = QApplication.instance()
    if app is None:
        return False
    return app.palette().color(QPalette.Window).lightness() < 128


# --------------------------------------------------------------------- worker
class ScanWorker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, root: Path, model_path: Optional[Path], use_acl: bool,
                 use_archives: bool, otinspect_path: Optional[Path] = None) -> None:
        super().__init__()
        self.root = root
        self.model_path = model_path
        self.use_acl = use_acl
        self.use_archives = use_archives
        self.otinspect_path = otinspect_path

    def run(self) -> None:
        try:
            catalogue = Catalogue.load()
            rules = RuleSet.load()
            amap = AttackMap.load()
            apply_to_rules(amap, rules)
            model = SiteModel.load(self.model_path) if self.model_path else SiteModel()
            reader = AclReader(enabled=self.use_acl)

            objects: List[DataObject] = []
            members: List[DataObject] = []
            for n, obj in enumerate(walk(self.root), start=1):
                klass, reason, confidence = catalogue.classify(obj.path, obj.head)
                obj.class_id, obj.class_reason, obj.confidence = klass.id, reason, confidence
                obj.acl = reader.for_file(obj.path, obj.mode)
                objects.append(obj)
                if self.use_archives and is_archive(obj.path):
                    members.extend(expand(obj, catalogue))
                if n % 100 == 0:
                    self.progress.emit(f"{n} files read")
            objects.extend(members)
            if self.otinspect_path:
                from . import otinspect
                self.progress.emit("reading the OTInspect report")
                otinspect.attach(objects, otinspect.load(self.otinspect_path))
            if not objects:
                self.failed.emit("No files found in that folder.")
                return
            self.progress.emit("scoring")
            assess(objects, catalogue, rules, model)
            amap.annotate(objects)
            attack_summary = aggregate(objects, amap)
            summary = build_summary(objects, catalogue, model, self.root)
            self.finished.emit((objects, catalogue, rules, model, summary,
                                reader.backend, attack_summary))
        except Exception:
            self.failed.emit(traceback.format_exc(limit=3))


# ---------------------------------------------------------------------- model
def compact_path(rel: str, limit: int = 58) -> str:
    """Keep the end of a path, which is the part that identifies the file."""
    if len(rel) <= limit:
        return rel
    parts = rel.split("/")
    tail = parts[-1]
    if len(tail) > limit:
        return "..." + tail[-(limit - 3):]
    out = tail
    for part in reversed(parts[:-1]):
        candidate = f"{part}/{out}"
        if len(candidate) + 4 > limit:
            break
        out = candidate
    return ".../" + out


class ObjectModel(QAbstractTableModel):
    HEADERS = ["Risk", "Severity", "Object", "Class", "Match", "Zone", "Owner", "Findings"]

    def __init__(self, theme: dict) -> None:
        super().__init__()
        self.rows: List[DataObject] = []
        self.catalogue: Optional[Catalogue] = None
        self.theme = theme

    def load(self, objects: List[DataObject], catalogue: Catalogue) -> None:
        self.beginResetModel()
        self.rows = sorted(objects, key=lambda o: (-o.risk, o.rel))
        self.catalogue = catalogue
        self.endResetModel()

    def rowCount(self, parent=None) -> int:
        return 0 if (parent is not None and parent.isValid()) else len(self.rows)

    def columnCount(self, parent=None) -> int:
        return 0 if (parent is not None and parent.isValid()) else len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.HEADERS[section]
        return None

    def object_at(self, row: int) -> Optional[DataObject]:
        return self.rows[row] if 0 <= row < len(self.rows) else None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        obj = self.rows[index.row()]
        col = index.column()
        if role == Qt.DisplayRole:
            klass = self.catalogue.get(obj.class_id) if self.catalogue else None
            return [
                obj.risk, obj.severity, compact_path(obj.rel),
                klass.title if klass else obj.class_id, obj.confidence,
                obj.zone_id or "-", obj.owner or "-",
                ", ".join(sorted({f["id"] for f in obj.findings})) or "-",
            ][col]
        if role == Qt.UserRole:            # sort key
            return obj.risk if col == 0 else self.data(index, Qt.DisplayRole)
        if role == Qt.ForegroundRole and col in (0, 1):
            return QColor(self.theme[obj.severity])
        if role == Qt.FontRole and col in (0, 1):
            font = QFont()
            font.setBold(obj.severity in ("critical", "high"))
            return font
        if role == Qt.TextAlignmentRole and col == 0:
            return int(Qt.AlignRight | Qt.AlignVCenter)
        if role == Qt.ToolTipRole:
            return obj.rel
        return None


class ObjectFilter(QSortFilterProxyModel):
    def __init__(self) -> None:
        super().__init__()
        self.severity = "all"
        self.needle = ""
        self.setSortRole(Qt.UserRole)

    def set_severity(self, value: str) -> None:
        self.severity = value
        self.invalidateFilter()

    def set_needle(self, value: str) -> None:
        self.needle = value.strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        model: ObjectModel = self.sourceModel()
        obj = model.object_at(row)
        if obj is None:
            return False
        if self.severity != "all" and obj.severity != self.severity:
            return False
        return not (self.needle and self.needle not in obj.rel.lower()
                    and self.needle not in obj.class_id)


# ----------------------------------------------------------------------- card
class Card(QFrame):
    def __init__(self, label: str, colour: Optional[str] = None) -> None:
        super().__init__()
        self.setObjectName("card")
        box = QVBoxLayout(self)
        box.setContentsMargins(14, 10, 14, 10)
        box.setSpacing(0)
        self.value = QLabel("-")
        self.value.setObjectName("cardValue")
        if colour:
            self.value.setStyleSheet(f"color: {colour};")
        name = QLabel(label.upper())
        name.setObjectName("cardLabel")
        box.addWidget(self.value)
        box.addWidget(name)

    def set(self, text: str) -> None:
        self.value.setText(text)


# ---------------------------------------------------------------------- window
class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.theme = DARK if palette_is_dark() else LIGHT
        self.setWindowTitle(f"OTDataMap {__version__}")
        self.resize(1240, 820)
        self.setStyleSheet(QSS.format(**self.theme))

        self.objects: List[DataObject] = []
        self.catalogue: Optional[Catalogue] = None
        self.rules = None
        self.model = SiteModel()
        self.scan_root: Optional[Path] = None
        self.attack_summary: Optional[dict] = None
        self.syllabus = Syllabus.load()
        self.amap = AttackMap.load()
        self.thread: Optional[QThread] = None

        self.table_model = ObjectModel(self.theme)
        self.proxy = ObjectFilter()
        self.proxy.setSourceModel(self.table_model)

        self._build()

    # ----------------------------------------------------------------- layout
    def _build(self) -> None:
        central = QWidget()
        outer = QVBoxLayout(central)
        outer.setContentsMargins(18, 16, 18, 12)
        outer.setSpacing(12)

        title = QLabel("OTDataMap")
        title.setObjectName("h1")
        subtitle = QLabel("Data classification and risk for OT/ICS folders. "
                          "Files are only read, never changed.")
        subtitle.setObjectName("sub")
        outer.addWidget(title)
        outer.addWidget(subtitle)

        # inputs
        row = QHBoxLayout()
        row.setSpacing(8)
        self.folder = QLineEdit()
        self.folder.setPlaceholderText("Folder to scan")
        browse = QPushButton("Browse")
        browse.clicked.connect(self._pick_folder)
        self.model_path = QLineEdit()
        self.model_path.setPlaceholderText("Site model (optional)")
        browse_model = QPushButton("Browse")
        browse_model.clicked.connect(self._pick_model)
        self.otinspect_path = QLineEdit()
        self.otinspect_path.setPlaceholderText("OTInspect report (optional)")
        browse_oti = QPushButton("Browse")
        browse_oti.clicked.connect(self._pick_otinspect)
        row.addWidget(self.folder, 3)
        row.addWidget(browse)
        row.addWidget(self.model_path, 2)
        row.addWidget(browse_model)
        row.addWidget(self.otinspect_path, 2)
        row.addWidget(browse_oti)
        outer.addLayout(row)

        row2 = QHBoxLayout()
        self.acl_box = QCheckBox("Read access control lists")
        self.acl_box.setChecked(True)
        self.archive_box = QCheckBox("Look inside archives")
        self.archive_box.setChecked(True)
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(self._start_scan)
        self.bar = QProgressBar()
        self.bar.setRange(0, 0)
        self.bar.setVisible(False)
        self.bar.setFixedWidth(160)
        row2.addWidget(self.acl_box)
        row2.addWidget(self.archive_box)
        row2.addStretch(1)
        row2.addWidget(self.bar)
        row2.addWidget(self.scan_btn)
        outer.addLayout(row2)

        # cards
        self.cards_row = QHBoxLayout()
        self.cards_row.setSpacing(10)
        self.cards = {"objects": Card("objects"), "volume": Card("volume"),
                      "restricted": Card("restricted")}
        for key in SEVERITIES:
            self.cards[key] = Card(key, self.theme[key])
        for card in self.cards.values():
            self.cards_row.addWidget(card)
        outer.addLayout(self.cards_row)

        # filters
        row3 = QHBoxLayout()
        row3.setSpacing(6)
        self.chips = {}
        for key in ["all"] + SEVERITIES:
            chip = QPushButton(key)
            chip.setObjectName("chip")
            chip.setCheckable(True)
            chip.setChecked(key == "all")
            chip.clicked.connect(lambda _c, k=key: self._set_severity(k))
            self.chips[key] = chip
            row3.addWidget(chip)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by path or class")
        self.search.textChanged.connect(self.proxy.set_needle)
        row3.addWidget(self.search, 1)
        learn_btn = QPushButton("What is this?")
        learn_btn.setToolTip("Explain the selected file: what this kind of OT data is, "
                             "how it looks from the other side, and what it buys an "
                             "adversary")
        learn_btn.clicked.connect(self._show_lesson)
        row3.addWidget(learn_btn)
        for text, slot in (("Save HTML", self._save_html), ("CSV", self._save_csv),
                           ("JSON", self._save_json)):
            btn = QPushButton(text)
            btn.clicked.connect(slot)
            row3.addWidget(btn)
        outer.addLayout(row3)

        # table + detail
        split = QSplitter(Qt.Vertical)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setDefaultSectionSize(26)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        for col, width in enumerate([62, 82, 360, 190, 80, 120, 150, 240]):
            self.table.setColumnWidth(col, width)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.selectionModel().selectionChanged.connect(self._show_detail)
        self.table.doubleClicked.connect(self._show_lesson)
        split.addWidget(self.table)

        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(False)
        self.detail.setHtml(self._placeholder())
        split.addWidget(self.detail)
        split.setSizes([480, 300])
        outer.addWidget(split, 1)

        self.setCentralWidget(central)
        self.statusBar().showMessage("Pick a folder and press Scan.")

    def _placeholder(self) -> str:
        return (f"<div style='color:{self.theme['muted']};padding:10px'>"
                "Select a row to see why it was flagged: the rule that matched, "
                "who can read it, and each finding with its remediation.</div>")

    # ------------------------------------------------------------------ input
    def _pick_folder(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Folder to scan")
        if chosen:
            self.folder.setText(chosen)

    def _pick_model(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, "Site model", "",
                                                "YAML (*.yaml *.yml);;All files (*)")
        if chosen:
            self.model_path.setText(chosen)

    def _pick_otinspect(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, "OTInspect JSON report", "",
                                                "JSON (*.json);;All files (*)")
        if chosen:
            self.otinspect_path.setText(chosen)

    def _set_severity(self, key: str) -> None:
        for name, chip in self.chips.items():
            chip.setChecked(name == key)
        self.proxy.set_severity(key)

    # ------------------------------------------------------------------- scan
    def _start_scan(self) -> None:
        folder = self.folder.text().strip()
        if not folder or not Path(folder).is_dir():
            QMessageBox.warning(self, "OTDataMap", "Choose a folder that exists.")
            return
        model_path = self.model_path.text().strip()
        if model_path and not Path(model_path).is_file():
            QMessageBox.warning(self, "OTDataMap", "That site model file does not exist.")
            return
        self.scan_root = Path(folder)
        self.scan_btn.setEnabled(False)
        self.bar.setVisible(True)
        self.statusBar().showMessage("Scanning...")

        self.thread = QThread(self)
        oti = self.otinspect_path.text().strip()
        self.worker = ScanWorker(self.scan_root,
                                 Path(model_path) if model_path else None,
                                 self.acl_box.isChecked(), self.archive_box.isChecked(),
                                 Path(oti) if oti else None)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(lambda m: self.statusBar().showMessage(m))
        self.worker.finished.connect(self._scan_done)
        self.worker.failed.connect(self._scan_failed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.start()

    def _stop_busy(self) -> None:
        self.bar.setVisible(False)
        self.scan_btn.setEnabled(True)

    def _scan_failed(self, message: str) -> None:
        self._stop_busy()
        self.statusBar().showMessage("Scan failed.")
        QMessageBox.critical(self, "OTDataMap", message)

    def _scan_done(self, payload) -> None:
        objects, catalogue, rules, model, summary, backend, attack_summary = payload
        self.attack_summary = attack_summary
        self.objects, self.catalogue = objects, catalogue
        self.rules, self.model = rules, model
        self._stop_busy()
        sev = summary["severity"]
        self.cards["objects"].set(str(summary["objects"]))
        self.cards["volume"].set(human_size(summary["bytes"]))
        self.cards["restricted"].set(str(summary["restricted_objects"]))
        for key in SEVERITIES:
            self.cards[key].set(str(sev.get(key, 0)))
        self.table_model.load(objects, catalogue)
        self.table.sortByColumn(0, Qt.DescendingOrder)
        self.detail.setHtml(self._placeholder())
        inside = sum(1 for o in objects if "!" in o.rel)
        extra = f", {inside} inside archives" if inside else ""
        techniques = len(attack_summary.get("techniques", []))
        tactics = len([t for t in attack_summary.get("tactics", []) if t["techniques"]])
        self.statusBar().showMessage(
            f"{summary['objects']} objects{extra} — access control: {backend}"
            f" — enables {techniques} ATT&CK ICS techniques across {tactics} tactics")

    # ---------------------------------------------------------------- details
    def _show_detail(self) -> None:
        obj = self._selected_object()
        if obj is None:
            return
        t = self.theme
        klass = self.catalogue.get(obj.class_id) if self.catalogue else None
        esc = lambda x: str(x).replace("&", "&amp;").replace("<", "&lt;")  # noqa: E731

        def line(label: str, value: str) -> str:
            return (f"<tr><td style='color:{t['muted']};padding:2px 14px 2px 0;"
                    f"white-space:nowrap'>{label}</td><td>{value}</td></tr>")

        head = (f"<div style='font-size:14px;font-weight:600'>{esc(obj.rel)}</div>"
                f"<div style='color:{t[obj.severity]};font-weight:600;margin:4px 0 8px'>"
                f"risk {obj.risk} &middot; {obj.severity}</div>")
        rows_html = [
            line("Class", f"{esc(klass.title if klass else obj.class_id)} "
                          f"<span style='color:{t['muted']}'>({esc(obj.class_id)}, "
                          f"matched by {esc(obj.class_reason)}, {esc(obj.confidence)} "
                          f"confidence)</span>"),
        ]
        if klass:
            rows_html.append(line("Sensitivity", f"{esc(klass.sensitivity)}, impact "
                                                 f"{esc(klass.impact)}"))
        if obj.devices:
            from .otinspect import describe
            rows_html.append(line("Describes", esc(describe(obj.devices))))
        rows_html.append(line("Zone", f"{esc(obj.zone_id or '-')} &middot; owner "
                                      f"{esc(obj.owner or '-')}"))
        rows_html.append(line("File", f"{human_size(obj.size)} &middot; modified "
                                      f"{obj.mtime:%Y-%m-%d}"))
        if obj.acl.available:
            rows_html.append(line("Access", esc(obj.acl.describe() or "no broad principal")
                                  + f" <span style='color:{t['muted']}'>"
                                    f"[{esc(obj.acl.source)}]</span>"))
        if obj.signals:
            rows_html.append(line("Signals",
                                  esc(", ".join(s["label"] for s in obj.signals))))
        if obj.attack:
            chips = " ".join(
                f"<span style='background:{t2['line']};border-radius:9px;"
                f"padding:1px 7px'>{esc(a['id'])} {esc(a['name'])}</span>"
                for a in obj.attack for t2 in [t])
            rows_html.append(line("Enables", chips))
        body = [head, "<table cellspacing='0'>", *rows_html, "</table>"]

        if obj.findings:
            body.append("<div style='margin-top:10px'></div>")
            for f in obj.findings:
                body.append(
                    f"<div style='border-left:3px solid {t[f['severity']]};"
                    f"padding:2px 0 6px 10px;margin:8px 0'>"
                    f"<b style='color:{t[f['severity']]}'>{esc(f['severity'].upper())}</b> "
                    f"<code>{esc(f['id'])}</code> &mdash; {esc(f['title'])}"
                    f"<div>{esc(f['detail'])}</div>"
                    f"<div style='color:{t['muted']};font-size:11px'>"
                    f"IEC 62443-3-3: {esc(', '.join(f['sr']) or '-')} &middot; "
                    f"ATT&amp;CK ICS: {esc(', '.join(f['attack']) or '-')}</div>"
                    f"<div style='margin-top:3px'>{esc(f['remediation'])}</div></div>")
        else:
            body.append(f"<div style='color:{t['muted']};margin-top:10px'>"
                        "No findings on this object.</div>")
        self.detail.setHtml("".join(body))

    # ------------------------------------------------------------------ learn
    def _selected_object(self) -> Optional[DataObject]:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        return self.table_model.object_at(self.proxy.mapToSource(rows[0]).row())

    def _lesson_html(self, lesson) -> str:
        t = self.theme

        def e(x):
            return str(x).replace("&", "&amp;").replace("<", "&lt;")

        parts = [f"<h2 style='margin:0'>{e(lesson.title)}</h2>",
                 f"<div style='color:{t['muted']};font-size:11px'>{e(lesson.id)} "
                 f"&middot; track {e(lesson.track)}</div>"]
        for label, body in (("What it is", lesson.what),
                            ("Coming from the other side", lesson.bridge),
                            ("Why it matters", lesson.why)):
            if body:
                parts.append(f"<h3 style='color:{t['muted']};font-size:11px;"
                             f"text-transform:uppercase;margin:14px 0 2px'>{label}</h3>"
                             f"<div>{e(body)}</div>")
        notes = attacker_note(lesson, self.amap)
        if notes:
            items = "".join(f"<li>{e(n)}</li>" for n in notes[1:])
            parts.append(f"<h3 style='color:{t['muted']};font-size:11px;"
                         f"text-transform:uppercase;margin:14px 0 2px'>What an "
                         f"adversary gains</h3><div>{e(notes[0])}</div>"
                         f"<ul>{items}</ul>")
        if lesson.check:
            parts.append(f"<h3 style='color:{t['muted']};font-size:11px;"
                         f"text-transform:uppercase;margin:14px 0 2px'>Go and look"
                         f"</h3><ul>"
                         + "".join(f"<li>{e(c)}</li>" for c in lesson.check) + "</ul>")
        if lesson.terms:
            rows = "".join(f"<li><b>{e(term)}</b> &mdash; "
                           f"{e(self.syllabus.glossary.get(term, ''))}</li>"
                           for term in lesson.terms)
            parts.append(f"<h3 style='color:{t['muted']};font-size:11px;"
                         f"text-transform:uppercase;margin:14px 0 2px'>Terms</h3>"
                         f"<ul>{rows}</ul>")
        if lesson.read:
            parts.append(f"<h3 style='color:{t['muted']};font-size:11px;"
                         f"text-transform:uppercase;margin:14px 0 2px'>Read next</h3>"
                         f"<ul>" + "".join(f"<li>{e(r)}</li>" for r in lesson.read)
                         + "</ul>")
        return "".join(parts)

    def _show_lesson(self) -> None:
        obj = self._selected_object()
        if obj is None:
            QMessageBox.information(self, "OTDataMap",
                                    "Select a row first, then press What is this?")
            return
        lesson = self.syllabus.for_class(obj.class_id)
        if lesson is None:
            QMessageBox.information(self, "OTDataMap",
                                    f"No lesson yet for {obj.class_id}.")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(lesson.title)
        dialog.resize(760, 620)
        dialog.setStyleSheet(QSS.format(**self.theme))
        box = QVBoxLayout(dialog)
        view = QTextBrowser()
        view.setOpenExternalLinks(False)
        view.setHtml(self._lesson_html(lesson))
        box.addWidget(view)
        close = QPushButton("Close")
        close.clicked.connect(dialog.accept)
        bottom = QHBoxLayout()
        bottom.addStretch(1)
        bottom.addWidget(close)
        box.addLayout(bottom)
        dialog.exec_()

    # ------------------------------------------------------------------ saves
    def _ready(self) -> bool:
        if not self.objects:
            QMessageBox.information(self, "OTDataMap", "Run a scan first.")
            return False
        return True

    def _ask(self, suffix: str, kind: str) -> Optional[Path]:
        chosen, _ = QFileDialog.getSaveFileName(
            self, "Save", f"otdatamap_report{suffix}", f"{kind} (*{suffix})")
        return Path(chosen) if chosen else None

    def _write(self, path: Path, text: str) -> None:
        try:
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "OTDataMap", f"Could not write {path}:\n{exc}")
            return
        self.statusBar().showMessage(f"Saved {path}")

    def _save_html(self) -> None:
        if self._ready():
            path = self._ask(".html", "HTML report")
            if path:
                self._write(path, to_html(self.objects, self.catalogue, self.rules,
                                          self.model, self.scan_root,
                                          attack_summary=self.attack_summary))

    def _save_csv(self) -> None:
        if self._ready():
            path = self._ask(".csv", "CSV inventory")
            if path:
                self._write(path, to_csv(self.objects, self.catalogue))

    def _save_json(self) -> None:
        if self._ready():
            path = self._ask(".json", "JSON output")
            if path:
                self._write(path, to_json(self.objects, self.catalogue, self.model,
                                          self.scan_root, self.attack_summary))


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("OTDataMap")
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
