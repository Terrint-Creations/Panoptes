"""Panoptes desktop app (PySide6). Same engine as the CLI, rendered live."""
from __future__ import annotations

import asyncio
import html
import json
import sys
import time
from urllib.parse import parse_qs, quote, urlparse

from PySide6.QtCore import QObject, QPointF, QRectF, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import (QAction, QBrush, QColor, QDesktopServices, QFont, QGuiApplication, QIcon, QPainter,
                           QPalette, QPen, QPixmap, QRadialGradient)
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
                               QFileDialog, QFormLayout, QGraphicsEllipseItem, QGraphicsScene, QGraphicsSimpleTextItem,
                               QGraphicsView, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
                               QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSlider,
                               QSpinBox, QSplitter, QTableWidget, QTableWidgetItem, QTabWidget, QTextBrowser,
                               QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from panoptes import __version__
from panoptes.config import KNOWN_KEYS, Config
from panoptes.detect import parse_target
from panoptes.engine import LOG_FILE, Engine, Events, investigation_options, make_client
from panoptes.models import KINDS, Entity, Finding, Report
from panoptes.report import SEV_ORDER, category_rank, export, graph_data
from panoptes.sources import SOURCES, SearchOptions
from panoptes.sources import accounts as accounts_mod
from panoptes.sources import sitedb
from panoptes import storage

ACCENT = "#d4a017"
CATEGORY_COLORS = {"account": "#3fb950", "profile": "#58a6ff", "email": "#d2a8ff", "breach": "#f85149",
                   "exposure": "#f85149", "registration": "#79c0ff", "dns": "#79c0ff", "geolocation": "#e3b341",
                   "network": "#e3b341", "subdomain": "#8b949e", "lead": "#8b949e", "web": "#58a6ff",
                   "phone": "#58a6ff", "key": "#d2a8ff", "archive": "#8b949e", "summary": ACCENT, "insight": "#f85149",
                   "threat": "#f85149", "lookalike": "#f0883e", "person": "#ffa657", "location": "#e3b341",
                   "wallet": "#f778ba", "file": "#a5d6ff", "metadata": "#8b949e", "software": "#8b949e",
                   "url": "#8b949e", "tls": "#79c0ff", "related-domain": "#79c0ff", "image": "#a5d6ff",
                   "alt-account": "#56d364", "face": "#ffa657", "face-match": "#ff7b72", "image-link": "#ffa657",
                   "image-match": "#a5d6ff", "darkweb": "#bc8cff", "onion": "#bc8cff", "associate": "#79c0ff",
                   "activity": "#8b949e", "relationship": "#d2a8ff", "company": "#79c0ff", "geo": "#e3b341",
                   "sun": "#e3b341", "weather": "#e3b341"}
SEV_COLORS = {"high": "#f85149", "medium": "#d29922", "low": "#58a6ff", "info": "#8b949e"}
NODE_COLORS = {"username": "#3fb950", "email": "#d2a8ff", "domain": "#79c0ff", "ip": "#e3b341", "phone": "#58a6ff",
               "name": "#ffa657", "crypto": "#f778ba", "file": "#a5d6ff", "account": "#2ea043", "breach": "#f85149",
               "location": "#e3b341", "related-domain": "#79c0ff", "lookalike": "#f0883e", "person": "#ffa657",
               "wallet": "#f778ba"}

STYLE = f"""
QWidget {{ background: #0d1117; color: #e6edf3; font-size: 13px; }}
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextBrowser, QTreeWidget, QTableWidget {{
    background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 5px; selection-background-color: #1f6feb; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {ACCENT}; }}
QLineEdit#target {{ font-size: 16px; padding: 9px 12px; }}
QPushButton, QToolButton {{ background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 7px 14px; }}
QPushButton:hover, QToolButton:hover {{ border-color: #8b949e; }}
QPushButton#primary {{ background: {ACCENT}; color: #0d1117; font-weight: 600; border: none; padding: 9px 22px; }}
QPushButton#primary:disabled {{ background: #5c4a14; color: #8b949e; }}
QPushButton#danger {{ background: #da3633; color: white; border: none; padding: 9px 18px; }}
QHeaderView::section {{ background: #161b22; color: #8b949e; border: none; border-bottom: 1px solid #30363d; padding: 6px; }}
QTreeWidget::item {{ padding: 3px 0; }}
QTreeWidget::item:selected, QTableWidget::item:selected {{ background: #1f6feb55; }}
QTabWidget::pane {{ border: 1px solid #30363d; border-radius: 6px; top: -1px; }}
QTabBar::tab {{ background: transparent; color: #8b949e; padding: 7px 14px; border-bottom: 2px solid transparent; }}
QTabBar::tab:selected {{ color: #e6edf3; border-bottom: 2px solid {ACCENT}; }}
QProgressBar {{ background: #21262d; border: none; border-radius: 4px; height: 8px; text-align: center; color: transparent; }}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 4px; }}
QMenu {{ background: #161b22; border: 1px solid #30363d; }} QMenu::item:selected {{ background: #1f6feb55; }}
QMenuBar {{ background: #0d1117; }} QMenuBar::item:selected {{ background: #21262d; }}
QStatusBar {{ color: #8b949e; }}
QSplitter::handle {{ background: #30363d; }}
QCheckBox::indicator {{ width: 15px; height: 15px; }}
QLabel#muted {{ color: #8b949e; }}
"""


def eye_icon(size: int = 128) -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    c = size / 2
    p.setPen(QPen(QColor(ACCENT), size * 0.07))
    p.setBrush(QColor("#0d1117"))
    p.drawEllipse(QRectF(size * 0.06, size * 0.06, size * 0.88, size * 0.88))
    grad = QRadialGradient(QPointF(c, c), size * 0.26)
    grad.setColorAt(0, QColor("#ffe08a"))
    grad.setColorAt(1, QColor(ACCENT))
    p.setPen(Qt.NoPen)
    p.setBrush(QBrush(grad))
    p.drawEllipse(QPointF(c, c), size * 0.25, size * 0.25)
    p.setBrush(QColor("#0d1117"))
    p.drawEllipse(QPointF(c, c), size * 0.11, size * 0.11)
    p.setBrush(QColor("#ffffff"))
    p.drawEllipse(QPointF(c - size * 0.07, c - size * 0.07), size * 0.035, size * 0.035)
    p.end()
    return QIcon(pm)


# ----------------------------------------------------------------------------- background workers

class Bridge(QObject, Events):
    """Engine callbacks (worker thread) -> Qt signals (GUI thread)."""
    entity = Signal(object, int, object)
    finding = Signal(object, bool)
    progress = Signal(str, object, int, int)
    source_start = Signal(str, object)
    source_done = Signal(str, object, int, object)
    log = Signal(str, str)

    def on_entity(self, entity, depth, via): self.entity.emit(entity, depth, via)
    def on_finding(self, finding, is_new): self.finding.emit(finding, is_new)
    def on_progress(self, source, entity, done, total): self.progress.emit(source, entity, done, total)
    def on_source_start(self, source, entity): self.source_start.emit(source, entity)
    def on_source_done(self, source, entity, count, error): self.source_done.emit(source, entity, count, error)
    def on_log(self, level, message): self.log.emit(level, message)


class SearchWorker(QThread):
    done = Signal(object)

    def __init__(self, targets: list[Entity], options: SearchOptions, bridge: Bridge, report: Report | None = None,
                 via: str | None = None):
        super().__init__()
        self.targets, self.bridge, self.base_report, self.via = targets, bridge, report, via
        self.engine = Engine(Config.load(), options, bridge)
        self.loop: asyncio.AbstractEventLoop | None = None
        self.task: asyncio.Task | None = None

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.task = self.loop.create_task(self.engine.run(self.targets, report=self.base_report, via=self.via))
        try:
            self.loop.run_until_complete(self.task)
        except asyncio.CancelledError:
            self.bridge.log.emit("warning", "Search stopped - building the summary from what was found")
            try:
                self.loop.run_until_complete(self.engine.wrap_up())
            except Exception as exc:
                self.bridge.log.emit("error", f"Summary after stop failed: {exc}")
        except Exception as exc:
            self.bridge.log.emit("error", f"Search failed: {exc}")
        finally:
            pending = asyncio.all_tasks(self.loop)
            for t in pending:
                t.cancel()
            if pending:
                self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self.loop.close()
        if self.engine.report and not self.engine.report.finished:
            self.engine.report.finished = time.time()
        self.done.emit(self.engine.report)

    def stop(self):
        if self.loop and self.task and not self.task.done():
            self.loop.call_soon_threadsafe(self.task.cancel)


class UpdateWorker(QThread):
    message = Signal(str)
    done = Signal(object)

    def run(self):
        async def go():
            async with make_client(Config.load(), SearchOptions()) as client:
                return await sitedb.update_databases(client, force=True, log=self.message.emit)
        try:
            counts = asyncio.run(go())
            accounts_mod._catalog_cache.clear()
            self.message.emit("Merging catalog…")
            self.done.emit((counts, sitedb.catalog_stats()))
        except Exception as exc:
            self.done.emit(exc)


# ----------------------------------------------------------------------------- dialogs

CAPABILITIES = [
    ("cooperative", "Cooperative mode", "Sources share high-confidence facts to cross-verify each other's findings"),
    ("faces", "Face recognition", "Detect and match faces locally across target photos and profile pictures"),
    ("reverse_image", "Reverse image search", "Search the web for where target photos and avatars appear. "
                                              "Local photos are uploaded to Yandex for this - untick to keep them local."),
    ("alt_accounts", "Alt-account finder", "Look for alternate accounts on the same platforms (evidence required)"),
    ("discover_sites", "Learn new sites", "Check sites linked from found profiles and remember them for future searches"),
    ("darkweb", "Dark-web index", "Look for mentions on indexed .onion pages (Ahmia)"),
    ("websearch", "Search engines, news & records", "Bing dorks, Google News/GDELT, Wikipedia, ORCID, Interpol, FBI, FEC"),
    ("ocr", "Read text in images", "OCR for coordinates, addresses, signs, handles in photos and screenshots"),
    ("ai_vision", "AI image analysis", "Claude describes images and estimates where they were taken (needs anthropic_api_key)"),
    ("geoai", "Visual geolocation", "AI estimates where a photo was taken from its content (online Picarta; GeoCLIP if installed)"),
]


class SettingsDialog(QDialog):
    """API keys, account logins/sessions and network settings - grouped, each with how to get it."""

    def __init__(self, parent=None):
        from panoptes.config import KEY_GROUPS, SECRET_KEYS

        super().__init__(parent)
        self.setWindowTitle("Settings - keys, logins & network")
        self.setMinimumWidth(760)
        self.cfg = Config.load()
        self.fields: dict[str, QLineEdit] = {}
        tabs = QTabWidget()
        notes = {
            "API keys": "All optional. Sources that need a missing key are skipped automatically.",
            "Logins & sessions": "Session cookies let Panoptes see what a logged-in user sees (like Toutatis / Instaloader). "
                                 "Use a separate burner account - automated lookups can get an account rate-limited. "
                                 "Stored only on this computer in ~/.panoptes/config.toml.",
            "Network": "Tor lets Panoptes scan .onion services. Leave empty if you don't use it.",
        }
        for group, keys in KEY_GROUPS.items():
            page = QWidget()
            lay = QVBoxLayout(page)
            note = QLabel(notes.get(group, ""))
            note.setWordWrap(True)
            note.setObjectName("muted")
            lay.addWidget(note)
            form = QFormLayout()
            for key, (desc, how) in keys.items():
                edit = QLineEdit(self.cfg.items().get(key, ""))
                edit.setPlaceholderText(desc)
                edit.setToolTip(f"{desc}\nHow to get it: {how}")
                if key in SECRET_KEYS:
                    edit.setEchoMode(QLineEdit.PasswordEchoOnEdit)
                self.fields[key] = edit
                hint = QLabel(f"<span style='color:#8b949e;font-size:11px'>{html.escape(desc)} · {html.escape(how)}</span>")
                hint.setWordWrap(True)
                box = QVBoxLayout()
                box.setSpacing(1)
                box.addWidget(edit)
                box.addWidget(hint)
                form.addRow(key, box)
            lay.addLayout(form)
            if group == "Logins & sessions":
                from panoptes import sessions
                lbl = QLabel("<b>Any other site</b> that blocks anonymous checks (Facebook, LinkedIn, Pinterest…): log in "
                             "with a burner account in your browser, open DevTools → Network, click any request to the "
                             "site and copy its <i>Cookie</i> request header. One site per line: "
                             "<code>facebook.com = c_user=…; xs=…</code>. Each cookie is only ever sent to its own site.")
                lbl.setWordWrap(True)
                lay.addWidget(lbl)
                self.site_sessions = QPlainTextEdit(sessions.to_text(sessions.load()))
                self.site_sessions.setPlaceholderText("facebook.com = c_user=…; xs=…" + chr(10) + "linkedin.com = li_at=…")
                self.site_sessions.setFixedHeight(110)
                lay.addWidget(self.site_sessions)
            lay.addStretch(1)
            tabs.addTab(page, group.replace("&", "&&"))
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(tabs)
        env = QLabel("Environment variables named PANOPTES_<KEY> override these values.")
        env.setObjectName("muted")
        lay.addWidget(env)
        lay.addWidget(buttons)

    def save(self):
        for key, edit in self.fields.items():
            self.cfg.set(key, edit.text().strip() or None)
        self.cfg.save()
        from panoptes import sessions
        sessions.save(sessions.from_text(self.site_sessions.toPlainText()))
        self.accept()


class InvestigationDialog(QDialog):
    """The full-investigation form: everything known about a subject, every capability switched on."""

    FIELDS = [("name", "Full name", "Jane Doe"), ("username", "Usernames", "jdoe, jane_d"),
              ("email", "Emails", "jane@example.com"), ("phone", "Phone numbers", "+1 555 010 0000"),
              ("domain", "Websites / domains", "example.com"), ("ip", "IP addresses", "203.0.113.7"),
              ("company", "Companies / organisations", "Acme Ltd; Example Inc  (separate with ;)"),
              ("location", "Places / coordinates", "Portland, OR; 40.6892, -74.0445  (separate with ;)"),
              ("crypto", "Crypto wallets", "bc1… / 0x…"), ("onion", ".onion sites", "needs Tor proxy in Settings"),
              ("file", "Images / documents", "paths or URLs")]
    SEMICOLON = {"company", "location"}

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Full investigation")
        self.setMinimumWidth(700)
        lay = QVBoxLayout(self)
        intro = QLabel(f"<span style='color:{ACCENT};font-size:17px;font-weight:600'>◉ Full investigation</span><br>"
                       "<span style='color:#8b949e'>Fill in whatever you know - every field is optional. Separate multiple "
                       "values with commas (semicolons for companies and places). Panoptes runs every capability on "
                       "every item, follows what it discovers, cross-verifies it, then correlates everything into one case."
                       "</span>")
        intro.setWordWrap(True)
        lay.addWidget(intro)
        form = QFormLayout()
        self.case = QLineEdit("Investigation")
        form.addRow("Case name", self.case)
        self.inputs: dict[str, QLineEdit] = {}
        for key, label, hint in self.FIELDS:
            edit = QLineEdit()
            edit.setPlaceholderText(hint)
            self.inputs[key] = edit
            if key == "file":
                row = QHBoxLayout()
                row.addWidget(edit, 1)
                browse = QPushButton("Browse…")
                browse.clicked.connect(self._browse)
                row.addWidget(browse)
                form.addRow(label, row)
            else:
                form.addRow(label, edit)
        self.notes = QPlainTextEdit()
        self.notes.setPlaceholderText("Context, what you're looking for, known facts…")
        self.notes.setFixedHeight(60)
        form.addRow("Notes", self.notes)
        lay.addLayout(form)

        box = QGroupBox("Options")
        grid = QGridLayout(box)
        self.depth = QSpinBox()
        self.depth.setRange(0, 4)
        self.depth.setValue(2)
        self.scope = QComboBox()
        self.scope.addItems(["quick", "standard", "full"])
        self.scope.setCurrentText("full")
        self.active = QCheckBox("Active recon (DNS brute force, zone transfer, lookalikes)")
        self.active.setChecked(True)
        self.perms = QCheckBox("Search usernames generated from the full name")
        self.perms.setChecked(True)
        self.nsfw = QCheckBox("Include NSFW sites")
        grid.addWidget(QLabel("Pivot depth"), 0, 0)
        grid.addWidget(self.depth, 0, 1)
        grid.addWidget(QLabel("Site scope"), 0, 2)
        grid.addWidget(self.scope, 0, 3)
        grid.addWidget(self.active, 1, 0, 1, 2)
        grid.addWidget(self.perms, 1, 2, 1, 2)
        grid.addWidget(self.nsfw, 2, 0, 1, 2)
        self.caps: dict[str, QCheckBox] = {}
        for i, (key, label, tip) in enumerate(CAPABILITIES):
            cb = QCheckBox(label)
            cb.setChecked(True)
            cb.setToolTip(tip)
            self.caps[key] = cb
            grid.addWidget(cb, 3 + i // 2, (i % 2) * 2, 1, 2)
        lay.addWidget(box)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Launch investigation")
        buttons.button(QDialogButtonBox.Ok).setObjectName("primary")
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def _browse(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose images or documents", "",
                                                "Media & documents (*.jpg *.jpeg *.png *.tif *.tiff *.heic *.webp *.gif "
                                                "*.pdf *.docx *.xlsx *.pptx);;All files (*)")
        if paths:
            cur = [v for v in self.inputs["file"].text().split(",") if v.strip()]
            self.inputs["file"].setText(", ".join(cur + paths))

    def values(self) -> dict[str, list[str]]:
        out = {}
        for key, edit in self.inputs.items():
            raw = edit.text().strip()
            if key == "name":
                out[key] = [raw] if raw else []
            else:
                sep = ";" if key in self.SEMICOLON else ","
                out[key] = [v.strip() for v in raw.split(sep) if v.strip()]
        return out

    def _accept(self):
        if not any(self.values().values()):
            QMessageBox.information(self, "Panoptes", "Fill in at least one field.")
            return
        self.accept()

    def build(self) -> tuple[list[Entity], SearchOptions, dict]:
        vals = self.values()
        targets = [parse_target(v, kind) for kind, items in vals.items() for v in items]
        options = investigation_options(self.depth.value(), self.scope.currentText(), self.nsfw.isChecked(),
                                        not self.active.isChecked(), bool(vals["name"]) and self.perms.isChecked())
        for key, cb in self.caps.items():
            setattr(options, key, cb.isChecked())
        if Config.load().get("tor_proxy"):
            options.pivot_kinds |= {"onion"}
        meta = {"case": self.case.text().strip() or "Investigation", "notes": self.notes.toPlainText().strip(),
                "form": {k: v for k, v in vals.items() if v}}
        return targets, options, meta


class CasesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Saved cases")
        self.resize(860, 480)
        self.selected: int | None = None
        lay = QVBoxLayout(self)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ID", "Case", "Targets", "Findings", "Date"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.doubleClicked.connect(self._open)
        lay.addWidget(self.table)
        row = QHBoxLayout()
        delete = QPushButton("Delete")
        delete.clicked.connect(self._delete)
        row.addWidget(delete)
        row.addStretch(1)
        open_btn = QPushButton("Open")
        open_btn.setObjectName("primary")
        open_btn.clicked.connect(self._open)
        row.addWidget(open_btn)
        lay.addLayout(row)
        self._load()

    def _load(self):
        cases = storage.list_cases(500)
        self.table.setRowCount(len(cases))
        for r, c in enumerate(cases):
            for col, val in enumerate((c["id"], c["name"], ", ".join(c["targets"]), c["findings"],
                                       time.strftime("%Y-%m-%d %H:%M", time.localtime(c["created"])))):
                self.table.setItem(r, col, QTableWidgetItem(str(val)))

    def _current(self) -> int | None:
        r = self.table.currentRow()
        return int(self.table.item(r, 0).text()) if r >= 0 else None

    def _open(self):
        self.selected = self._current()
        if self.selected is not None:
            self.accept()

    def _delete(self):
        cid = self._current()
        if cid is not None and QMessageBox.question(self, "Delete case", f"Delete case #{cid}?") == QMessageBox.Yes:
            storage.delete_case(cid)
            self._load()


# ----------------------------------------------------------------------------- main window

ROLE_FINDING = Qt.UserRole + 1


def _dur(sec: float) -> str:
    sec = int(sec)
    return f"{sec // 60}m {sec % 60:02d}s" if sec >= 60 else f"{sec}s"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Panoptes")
        self.setWindowIcon(eye_icon())
        self.resize(1400, 880)
        self.worker: SearchWorker | None = None
        self.update_worker: UpdateWorker | None = None
        self.report: Report | None = None
        self.started_at = 0.0
        self.entity_items: dict[str, QTreeWidgetItem] = {}
        self.category_items: dict[tuple[str, str], QTreeWidgetItem] = {}
        self.finding_items: dict[tuple, QTreeWidgetItem] = {}
        self.activity_rows: dict[tuple, int] = {}
        self.pending: list[tuple[list[Entity], set[str] | None]] = []
        self.running: dict[tuple, tuple[float, str]] = {}
        self.source_actions: dict[str, QAction] = {}

        self._build_menu()
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 12, 16, 8)
        root.setSpacing(10)
        root.addLayout(self._build_search_bar())
        root.addLayout(self._build_options_bar())

        vsplit = QSplitter(Qt.Vertical)
        hsplit = QSplitter(Qt.Horizontal)
        hsplit.addWidget(self._build_results())
        self.right_tabs = QTabWidget()
        self.overview = QTextBrowser()
        self.overview.setOpenLinks(False)
        self.overview.anchorClicked.connect(self._on_link)
        self.overview.setHtml(self._welcome_html())
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.details.anchorClicked.connect(self._on_link)
        self.details.setHtml("<p style='color:#8b949e'>Select a finding to see its details.</p>")
        from panoptes.gui.graph import GraphPanel
        from panoptes.sources import sources_for
        self.graph = GraphPanel(sources_for)
        self.graph.node_selected.connect(self._graph_selected)
        self.graph.search_entity.connect(lambda e: self.extend_case([e]))
        self.graph.run_transform.connect(lambda e, src: self.extend_case([e], only={src}))
        self.images: dict[str, object] = {}
        self._detail_obj = None
        from PySide6.QtNetwork import QNetworkAccessManager
        self.net = QNetworkAccessManager(self)
        self.net.finished.connect(self._image_loaded)
        self.right_tabs.addTab(self.overview, "Overview")
        self.right_tabs.addTab(self.details, "Details")
        self.right_tabs.addTab(self.graph, "Graph")
        hsplit.addWidget(self.right_tabs)
        hsplit.setSizes([900, 520])
        self.meta: dict = {}
        vsplit.addWidget(hsplit)
        vsplit.addWidget(self._build_bottom_tabs())
        vsplit.setSizes([620, 220])
        root.addWidget(vsplit, 1)
        self.setCentralWidget(central)

        self.status_label = QLabel("Ready")
        self.statusBar().addWidget(self.status_label, 1)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)

    # ---- construction
    def _build_menu(self):
        mb = self.menuBar()
        m = mb.addMenu("&File")
        m.addAction("New full investigation…", self.open_investigation)
        m.addAction("Open saved case…", self.open_case)
        m.addSeparator()
        for label, ext in (("Export HTML report…", "html"), ("Export JSON…", "json"), ("Export CSV…", "csv"),
                           ("Export STIX 2.1 (OpenCTI/MISP)…", "stix.json")):
            act = m.addAction(label)
            act.triggered.connect(lambda _=False, e=ext: self.export(e))
        m.addSeparator()
        m.addAction("Quit", self.close)
        t = mb.addMenu("&Tools")
        t.addAction("Update site databases", self.update_databases)
        t.addAction("Settings - keys, logins & network…", lambda: SettingsDialog(self).exec() and self._refresh_sources())
        t.addSeparator()
        t.addAction("Open log folder", lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(LOG_FILE.parent))))
        h = mb.addMenu("&Help")
        h.addAction("About Panoptes", lambda: QMessageBox.about(
            self, "About Panoptes",
            f"<h3>◉ Panoptes {__version__}</h3><p>The all-seeing OSINT super tool.</p>"
            "<p>One search fans out to every relevant capability - account discovery across five merged site "
            "databases, email/phone registrations, breaches, social platforms, images and faces, GEOINT, "
            "companies, infrastructure and the dark web - cross-verifies the results, then follows what it finds.</p>"
            "<p>Use responsibly and lawfully.</p>"))

    def _build_search_bar(self):
        row = QHBoxLayout()
        logo = QLabel(f"<span style='color:{ACCENT};font-size:22px;font-weight:700;letter-spacing:3px'>◉ PANOPTES</span>")
        row.addWidget(logo)
        row.addSpacing(12)
        self.target = QLineEdit()
        self.target.setObjectName("target")
        self.target.setPlaceholderText("username, email, phone, domain, IP, URL, wallet, place, company or \"Full Name\""
                                       "  -  separate several with ;")
        self.target.returnPressed.connect(self.start_search)
        row.addWidget(self.target, 1)
        browse = QToolButton()
        browse.setText("📎")
        browse.setToolTip("Analyse an image or document")
        browse.clicked.connect(self._browse_file)
        row.addWidget(browse)
        self.kind = QComboBox()
        self.kind.addItems(["auto", "all"] + list(KINDS))
        self.kind.setToolTip("Target type - auto-detected by default; 'all' tries every plausible interpretation")
        self.kind.setToolTip("Target type (auto-detected by default)")
        row.addWidget(self.kind)
        self.search_btn = QPushButton("Search")
        self.search_btn.setObjectName("primary")
        self.search_btn.clicked.connect(self.start_search)
        row.addWidget(self.search_btn)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("danger")
        self.stop_btn.clicked.connect(self.stop_search)
        self.stop_btn.setVisible(False)
        row.addWidget(self.stop_btn)
        self.invest_btn = QPushButton("Full investigation…")
        self.invest_btn.setToolTip("Fill out a form with everything you know and run every capability")
        self.invest_btn.clicked.connect(self.open_investigation)
        row.addWidget(self.invest_btn)
        return row

    def _build_options_bar(self):
        row = QHBoxLayout()
        row.addWidget(QLabel("Depth"))
        self.depth = QSpinBox()
        self.depth.setRange(0, 4)
        self.depth.setValue(1)
        self.depth.setToolTip("Pivot hops: follow emails, usernames, domains and IPs discovered along the way")
        row.addWidget(self.depth)
        row.addSpacing(10)
        row.addWidget(QLabel("Site scope"))
        self.scope = QComboBox()
        self.scope.addItems(["quick", "standard", "full"])
        self.scope.setCurrentText("standard")
        self.scope.setToolTip("quick: cross-validated sites · standard: ~1.4k sites · full: ~11k sites")
        row.addWidget(self.scope)
        row.addSpacing(10)
        self.verify = QCheckBox("Verify hits")
        self.verify.setChecked(True)
        self.verify.setToolTip("Re-check every account hit with a random username to drop false positives")
        self.disputed = QCheckBox("Show disputed")
        self.disputed.setToolTip("Include account hits where the databases disagree 50/50")
        self.nsfw = QCheckBox("NSFW sites")
        for w in (self.verify, self.disputed, self.nsfw):
            row.addWidget(w)
        row.addSpacing(10)
        self.sources_btn = QToolButton()
        self.sources_btn.setText("Sources ▾")
        self.sources_btn.setPopupMode(QToolButton.InstantPopup)
        menu = QMenu(self)
        for kind in KINDS:
            srcs = [s for s in SOURCES if kind in s.kinds and s.name not in self.source_actions]
            if not srcs:
                continue
            menu.addSection(kind.capitalize())
            for s in srcs:
                act = QAction(s.name, menu, checkable=True)
                act.setChecked(True)
                act.setToolTip(s.description)
                menu.addAction(act)
                self.source_actions[s.name] = act
        menu.setToolTipsVisible(True)
        self.sources_btn.setMenu(menu)
        row.addWidget(self.sources_btn)
        self.caps_btn = QToolButton()
        self.caps_btn.setText("Capabilities ▾")
        self.caps_btn.setPopupMode(QToolButton.InstantPopup)
        cmenu = QMenu(self)
        cmenu.setToolTipsVisible(True)
        self.cap_actions: dict[str, QAction] = {}
        for key, label, tip in CAPABILITIES:
            act = QAction(label, cmenu, checkable=True)
            act.setChecked(True)
            act.setToolTip(tip)
            cmenu.addAction(act)
            self.cap_actions[key] = act
        self.caps_btn.setMenu(cmenu)
        row.addWidget(self.caps_btn)
        row.addSpacing(10)
        row.addWidget(QLabel("Resources"))
        self.profile = QComboBox()
        self.profile.addItems(["light", "balanced", "heavy"])
        self.profile.setCurrentText("balanced")
        self.profile.setToolTip("Light: runs in the background at low priority with fewer parallel jobs - keep working "
                                "while it scans. Same checks and results as Heavy, only slower.")
        row.addWidget(self.profile)
        self._refresh_sources()
        row.addStretch(1)
        row.addWidget(QLabel("Filter"))
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("text…")
        self.filter.setFixedWidth(180)
        self.filter.textChanged.connect(self._apply_filter)
        row.addWidget(self.filter)
        row.addWidget(QLabel("Min conf."))
        self.min_conf = QSlider(Qt.Horizontal)
        self.min_conf.setRange(0, 95)
        self.min_conf.setFixedWidth(110)
        self.min_conf_label = QLabel("0%")
        self.min_conf.valueChanged.connect(lambda v: (self.min_conf_label.setText(f"{v}%"), self._apply_filter()))
        row.addWidget(self.min_conf)
        row.addWidget(self.min_conf_label)
        return row

    def _build_results(self):
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Finding", "Value", "Sources", "Conf."])
        self.tree.setAlternatingRowColors(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.SingleSelection)
        hdr = self.tree.header()
        hdr.setSectionResizeMode(0, QHeaderView.Interactive)
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.Interactive)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.tree.setColumnWidth(0, 260)
        self.tree.setColumnWidth(2, 210)
        self.tree.itemSelectionChanged.connect(self._show_details)
        self.tree.itemDoubleClicked.connect(self._open_item)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_menu)
        return self.tree

    def _build_bottom_tabs(self):
        tabs = QTabWidget()
        self.activity = QTableWidget(0, 4)
        self.activity.setHorizontalHeaderLabels(["Source", "Target", "Progress", "Status"])
        self.activity.verticalHeader().setVisible(False)
        self.activity.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.activity.setSelectionMode(QAbstractItemView.NoSelection)
        h = self.activity.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.Stretch)
        h.setSectionResizeMode(2, QHeaderView.Fixed)
        h.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.activity.setColumnWidth(2, 260)
        tabs.addTab(self.activity, "Activity")
        self.entities = QTableWidget(0, 3)
        self.entities.setHorizontalHeaderLabels(["Entity", "Depth", "Found via"])
        self.entities.verticalHeader().setVisible(False)
        self.entities.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.entities.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.entities.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        tabs.addTab(self.entities, "Entities")
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 10))
        tabs.addTab(self.log_view, "Log")
        return tabs

    def _refresh_sources(self):
        cfg = Config.load()
        for s in SOURCES:
            act = self.source_actions.get(s.name)
            if act:
                ok, why = s.available(cfg)
                act.setEnabled(ok)
                act.setText(s.name if ok else f"{s.name}  ({why})")

    # ---- search lifecycle
    def start_search(self):
        if self.worker and self.worker.isRunning():
            return
        raw = [t.strip() for t in self.target.text().split(";") if t.strip()]
        if not raw:
            self.target.setFocus()
            return
        try:
            from panoptes.detect import parse_all
            kind = self.kind.currentText()
            targets = [e for t in raw for e in (parse_all(t) if kind == "all" else [parse_target(t, kind)])]
        except ValueError as exc:
            QMessageBox.warning(self, "Panoptes", str(exc))
            return
        options = SearchOptions(depth=self.depth.value(), scope=self.scope.currentText(), nsfw=self.nsfw.isChecked(),
                                verify=self.verify.isChecked(), include_disputed=self.disputed.isChecked())
        for key, act in self.cap_actions.items():
            setattr(options, key, act.isChecked())
        self.launch(targets, options, {})

    def open_investigation(self):
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, "Panoptes", "A search is already running.")
            return
        dlg = InvestigationDialog(self)
        if dlg.exec():
            try:
                targets, options, meta = dlg.build()
            except ValueError as exc:
                QMessageBox.warning(self, "Panoptes", str(exc))
                return
            self.target.setText(" ; ".join(t.value for t in targets))
            self.launch(targets, options, meta)

    def launch(self, targets: list[Entity], options: SearchOptions, meta: dict):
        from panoptes.sources.base import apply_profile
        apply_profile(options, self.profile.currentText())
        options.include = {n for n, a in self.source_actions.items() if a.isChecked() and a.isEnabled()}
        self.meta = meta
        self._reset()
        self.right_tabs.setCurrentWidget(self.overview)
        self.overview.setHtml(f"<h3 style='color:{ACCENT}'>Searching…</h3><p style='color:#8b949e'>"
                              f"{html.escape(', '.join(map(str, targets)))}</p><p style='color:#8b949e'>The identity "
                              "summary, insights and graph appear here when the search completes.</p>")
        self.bridge = Bridge()
        self.bridge.entity.connect(self._on_entity)
        self.bridge.finding.connect(self._on_finding)
        self.bridge.progress.connect(self._on_progress)
        self.bridge.source_start.connect(self._on_source_start)
        self.bridge.source_done.connect(self._on_source_done)
        self.bridge.log.connect(self._on_log)
        self.worker = SearchWorker(targets, options, self.bridge)
        self.worker.done.connect(self._on_done)
        self.search_btn.setEnabled(False)
        self.stop_btn.setVisible(True)
        self.started_at = time.time()
        self.timer.start(500)
        self._on_log("info", f"Searching {', '.join(map(str, targets))} (depth {options.depth}, scope {options.scope})")
        self.worker.start()

    def stop_search(self):
        if self.worker:
            self.worker.stop()
            self.stop_btn.setEnabled(False)

    def _reset(self):
        self.tree.clear()
        self.entity_items.clear()
        self.category_items.clear()
        self.finding_items.clear()
        self.activity.setRowCount(0)
        self.activity_rows.clear()
        self.running.clear()
        self.entities.setRowCount(0)
        self.log_view.clear()
        self.report = None
        self.graph.render_report(None)

    def _on_done(self, report: Report | None):
        self.report = report
        self.timer.stop()
        self._tick()
        self.search_btn.setEnabled(True)
        self.stop_btn.setVisible(False)
        self.stop_btn.setEnabled(True)
        if report:
            report.meta.update(self.meta)
            elapsed = (report.finished or time.time()) - report.started
            case_note = ""
            if report.findings:
                try:
                    if getattr(self, "case_id", None) and getattr(self, "case_report", None) is report:
                        storage.update_case(self.case_id, report)
                        case_note = f" · case #{self.case_id} updated"
                    else:
                        self.case_id, self.case_report = storage.save_case(report), report
                        case_note = f" · saved as case #{self.case_id}"
                except Exception as exc:
                    self._on_log("error", f"Could not save case: {exc}")
            self.status_label.setText(f"Done · {len(report.findings)} findings across {len(report.entities)} "
                                      f"entities in {elapsed:.1f}s{case_note} · File ▸ Export to save a report")
            self._render_overview(report)
            self.graph.render_report(report)
        if self.pending:
            ents, only = self.pending.pop(0)
            QTimer.singleShot(200, lambda: self.extend_case(ents, only))
        for i in range(self.tree.topLevelItemCount()):
            self.tree.topLevelItem(i).setExpanded(True)

    def _render_overview(self, report: Report):
        e = html.escape
        summary = sorted((f for f in report.findings.values() if f.category == "summary"),
                         key=lambda f: (f.title, -f.confidence))
        insights = sorted((f for f in report.findings.values() if f.category == "insight"),
                          key=lambda f: SEV_ORDER.get(f.data.get("severity", "info"), 9))
        rows = "".join(f"<tr><td style='color:#8b949e;padding-right:12px'>{e(f.title)}</td><td>{e(f.value)}"
                       f"{'' if f.sources == {'correlation'} else '<br><small style=color:#8b949e>' + e(', '.join(sorted(f.sources))) + '</small>'}"
                       f"</td></tr>" for f in summary)
        ins = "".join(f"<p style='margin:6px 0'><span style='color:{SEV_COLORS.get(f.data.get('severity', 'info'))};"
                      f"font-weight:700'>{e(f.data.get('severity', 'info').upper())}</span> <b>{e(f.title)}</b><br>"
                      f"<span style='color:#c9d1d9'>{e(f.value)}</span> <small style='color:#8b949e'>· {e(str(f.target))}</small></p>"
                      for f in insights)
        case = report.meta.get("case")
        notes = report.meta.get("notes")
        self.overview.setHtml(f"""<div style="font-family:Segoe UI;color:#e6edf3">
        <h2 style="color:{ACCENT};margin-bottom:2px">{e(case or 'Overview')}</h2>
        <p style="color:#8b949e;margin-top:0">{len(report.findings)} findings · {len(report.entities)} entities</p>
        {f'<p style="color:#c9d1d9">{e(notes)}</p>' if notes else ''}
        <h3>Identity summary</h3><table cellpadding="3">{rows or '<tr><td>-</td></tr>'}</table>
        <h3>Insights</h3>{ins or '<p style="color:#8b949e">No notable insights.</p>'}</div>""")

    def open_case(self):
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, "Panoptes", "A search is running.")
            return
        dlg = CasesDialog(self)
        if dlg.exec() and dlg.selected is not None:
            report = storage.load_case(dlg.selected)
            if report is None:
                return
            self._reset()
            for ent, depth, via in report.entities.values():
                self._on_entity(ent, depth, via)
            for f in report.findings.values():
                self._on_finding(f, True)
            self.report = report
            self.meta = report.meta
            self.case_id, self.case_report = dlg.selected, report
            self._render_overview(report)
            self.graph.render_report(report)
            self.target.setText(" ; ".join(t.value for t in report.targets))
            self.status_label.setText(f"Opened case #{dlg.selected} · {len(report.findings)} findings")

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Analyse an image or document", "",
                                              "Media & documents (*.jpg *.jpeg *.png *.tif *.tiff *.heic *.webp *.gif "
                                              "*.pdf *.docx *.xlsx *.pptx);;All files (*)")
        if path:
            self.target.setText(path)
            self.kind.setCurrentText("file")
            self.start_search()

    def _tick(self):
        n = len(self.finding_items)
        now = time.time()
        for key, (since, progress) in self.running.items():
            row = self.activity_rows.get(key)
            if row is not None and self.activity.item(row, 3):
                self.activity.item(row, 3).setText(f"running · {_dur(now - since)}" + (f" · {progress}" if progress else ""))
        busy = sorted(self.running.items(), key=lambda kv: kv[1][0])[:3]
        still = ", ".join(f"{k[0]} ({_dur(now - v[0])})" for k, v in busy)
        state = "Searching" if self.worker and self.worker.isRunning() else "Finished"
        self.status_label.setText(f"{state} · {n} findings · {len(self.running)} sources running · "
                                  f"{_dur(now - self.started_at)}" + (f" · still working: {still}" if still else ""))

    # ---- event handlers
    def _on_entity(self, entity: Entity, depth: int, via):
        r = self.entities.rowCount()
        self.entities.insertRow(r)
        self.entities.setItem(r, 0, QTableWidgetItem(str(entity)))
        self.entities.setItem(r, 1, QTableWidgetItem(str(depth)))
        self.entities.setItem(r, 2, QTableWidgetItem(via or "search target"))
        self._entity_item(entity, depth, via)
        if depth:
            self._on_log("info", f"Pivot → {entity} (via {via})")

    def _entity_item(self, entity: Entity, depth: int = 0, via=None) -> QTreeWidgetItem:
        key = str(entity)
        item = self.entity_items.get(key)
        if item is None:
            item = QTreeWidgetItem([f"{'↳ ' if depth else '◉ '}{entity.value}", entity.kind, via or "", ""])
            f = item.font(0)
            f.setBold(True)
            f.setPointSize(f.pointSize() + 1)
            item.setFont(0, f)
            item.setForeground(0, QColor(ACCENT))
            item.setFirstColumnSpanned(False)
            self.tree.addTopLevelItem(item)
            item.setExpanded(True)
            self.entity_items[key] = item
        return item

    def _category_item(self, entity: Entity, category: str) -> QTreeWidgetItem:
        key = (str(entity), category)
        item = self.category_items.get(key)
        if item is None:
            parent = self._entity_item(entity)
            item = QTreeWidgetItem([category, "", "", ""])
            item.setForeground(0, QColor(CATEGORY_COLORS.get(category, "#e6edf3")))
            f = item.font(0)
            f.setBold(True)
            item.setFont(0, f)
            # keep categories in a stable, meaningful order
            idx = sum(1 for i in range(parent.childCount())
                      if category_rank(parent.child(i).data(0, ROLE_FINDING + 1) or "") <= category_rank(category))
            item.setData(0, ROLE_FINDING + 1, category)
            parent.insertChild(idx, item)
            item.setExpanded(category not in ("subdomain", "lead", "url", "metadata", "lookalike", "software",
                                              "image-match", "darkweb", "geo", "activity"))
            self.category_items[key] = item
        return item

    def _on_finding(self, f: Finding, is_new: bool):
        key = f.key()
        item = self.finding_items.get(key)
        if item is None:
            cat = self._category_item(f.target, f.category)
            item = QTreeWidgetItem()
            item.setData(0, ROLE_FINDING, f)
            cat.addChild(item)
            self.finding_items[key] = item
            cat.setText(1, f"{cat.childCount()}")
            cat.setForeground(1, QColor("#8b949e"))
        conf = int(f.confidence * 100)
        item.setText(0, f.title)
        item.setText(1, f.value)
        item.setText(2, ", ".join(sorted(f.sources)))
        item.setText(3, f"{conf}%")
        item.setForeground(3, QColor("#3fb950" if conf >= 80 else "#e3b341" if conf >= 60 else "#f85149"))
        item.setForeground(2, QColor("#8b949e"))
        if f.url:
            item.setForeground(1, QColor("#58a6ff"))
        item.setToolTip(1, f.url or f.value)
        if f.category == "insight":
            sev = f.data.get("severity", "info")
            item.setForeground(0, QColor(SEV_COLORS.get(sev, "#8b949e")))
            item.setText(3, sev.upper())
            item.setForeground(3, QColor(SEV_COLORS.get(sev, "#8b949e")))
        elif f.category == "summary":
            item.setForeground(0, QColor(ACCENT))
        self._filter_item(item)

    def _activity_row(self, source: str, entity: Entity) -> int:
        key = (source, str(entity))
        if key not in self.activity_rows:
            r = self.activity.rowCount()
            self.activity.insertRow(r)
            self.activity.setItem(r, 0, QTableWidgetItem(source))
            self.activity.setItem(r, 1, QTableWidgetItem(str(entity)))
            bar = QProgressBar()
            bar.setRange(0, 0)
            bar.setFixedHeight(8)
            holder = QWidget()
            lay = QHBoxLayout(holder)
            lay.setContentsMargins(6, 0, 6, 0)
            lay.addWidget(bar)
            self.activity.setCellWidget(r, 2, holder)
            self.activity.setItem(r, 3, QTableWidgetItem("running"))
            self.activity_rows[key] = r
        return self.activity_rows[key]

    def _bar(self, row: int) -> QProgressBar:
        return self.activity.cellWidget(row, 2).findChild(QProgressBar)

    def _on_source_start(self, source, entity):
        self._activity_row(source, entity)
        self.running[(source, str(entity))] = (time.time(), "")

    def _on_progress(self, source, entity, done, total):
        bar = self._bar(self._activity_row(source, entity))
        bar.setRange(0, max(total, 1))
        bar.setValue(done)
        key = (source, str(entity))
        if key in self.running:
            self.running[key] = (self.running[key][0], f"{done}/{total}")

    def _on_source_done(self, source, entity, count, error):
        self.running.pop((source, str(entity)), None)
        r = self._activity_row(source, entity)
        bar = self._bar(r)
        bar.setRange(0, 1)
        bar.setValue(1)
        status = self.activity.item(r, 3)
        status.setText(f"error: {error}" if error else f"{count} findings")
        status.setForeground(QColor("#f85149" if error else "#3fb950" if count else "#8b949e"))

    def _on_log(self, level: str, message: str):
        if level == "debug":
            return
        color = {"error": "ERROR", "warning": "WARN "}.get(level, "INFO ")
        self.log_view.appendPlainText(f"{time.strftime('%H:%M:%S')}  {color}  {message}")

    # ---- results interaction
    def _apply_filter(self):
        for item in self.finding_items.values():
            self._filter_item(item)
        for cat in self.category_items.values():
            cat.setHidden(all(cat.child(i).isHidden() for i in range(cat.childCount())))

    def _filter_item(self, item: QTreeWidgetItem):
        f: Finding = item.data(0, ROLE_FINDING)
        text = self.filter.text().strip().lower()
        hide = f.confidence * 100 < self.min_conf.value() or (
            text and text not in f.title.lower() and text not in f.value.lower()
            and not any(text in s for s in f.sources))
        item.setHidden(bool(hide))

    def _selected_finding(self) -> Finding | None:
        items = self.tree.selectedItems()
        return items[0].data(0, ROLE_FINDING) if items else None

    def _graph_selected(self, obj):
        if isinstance(obj, Finding):
            item = self.finding_items.get(obj.key())
            if item:
                self.tree.blockSignals(True)
                self.tree.setCurrentItem(item)
                self.tree.blockSignals(False)
            self._render_details(obj, switch=False)

    def _images_for(self, f: Finding) -> list[str]:
        urls = []
        if f.category in ("image", "face") and (f.url or f.value or "").startswith("http"):
            urls.append(f.url or f.value)
        for k in ("thumbnail", "avatar", "image"):
            v = f.data.get(k)
            if isinstance(v, str) and v.startswith("http"):
                urls.append(v)
        # The uploaded image is shown only for findings *about* it - a match shows the matched picture instead.
        if (f.category not in ("image-match", "web", "news", "lead") and f.target.kind == "file"
                and f.target.value.lower().split("?")[0].endswith((".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp",
                                                                   ".tif", ".tiff"))):
            urls.append(f.target.value)
        for p in f.data.get("places", []) if isinstance(f.data.get("places"), list) else []:
            for g in self.finding_items.values():
                gf = g.data(0, ROLE_FINDING)
                if gf.url == p and gf.data.get("avatar"):
                    urls.append(gf.data["avatar"])
        return list(dict.fromkeys(urls))[:6]

    def _image_html(self, urls: list[str]) -> str:
        from PySide6.QtGui import QImage
        from PySide6.QtNetwork import QNetworkRequest
        out = []
        for u in urls:
            if u not in self.images:
                if u.startswith("http"):
                    self.images[u] = None
                    req = QNetworkRequest(QUrl(u))
                    req.setRawHeader(b"User-Agent", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0 Safari/537.36")
                    self.net.get(req)
                else:
                    img = QImage(u)
                    self.images[u] = img if not img.isNull() else False
            img = self.images.get(u)
            if img:
                self.details.document().addResource(3, QUrl(u), img)  # 3 = QTextDocument.ImageResource
                w = min(360, img.width())
                out.append(f'<img src="{html.escape(u)}" width="{w}" style="margin:4px">')
            elif img is None:
                out.append('<span style="color:#8b949e">loading image…</span>')
        return " ".join(out)

    def _image_loaded(self, reply):
        from PySide6.QtGui import QImage
        u = reply.request().url().toString()
        img = QImage()
        ok = reply.error() == reply.NetworkError.NoError and img.loadFromData(reply.readAll())
        self.images[u] = img if ok else False
        reply.deleteLater()
        if isinstance(self._detail_obj, Finding) and u in self._images_for(self._detail_obj):
            self._render_details(self._detail_obj, switch=False)

    def _show_details(self):
        f = self._selected_finding()
        if not f:
            items = self.tree.selectedItems()
            if items and items[0].parent() is None and self.report:
                self._render_overview(self.report)
                self.right_tabs.setCurrentWidget(self.overview)
            return
        self._render_details(f)

    def _render_details(self, f: Finding, switch: bool = True):
        self._detail_obj = f
        if switch:
            self.right_tabs.setCurrentWidget(self.details)
        e = html.escape
        images = self._image_html(self._images_for(f))
        value = f'<a href="{e(f.url)}">{e(f.value)}</a>' if f.url else e(f.value)
        pivots = "".join(
            f'<li><a href="panoptes://search?kind={quote(p.kind)}&value={quote(p.value)}">Search {e(p.kind)}: '
            f'<b>{e(p.value)}</b></a></li>' for p in f.pivots)
        data = json.dumps(f.data, indent=2, ensure_ascii=False, default=str) if f.data else ""
        self.details.setHtml(f"""
        <div style="font-family:Segoe UI;color:#e6edf3">
        <div style="color:{CATEGORY_COLORS.get(f.category, ACCENT)};text-transform:uppercase;font-size:11px">{e(f.category)}</div>
        <h2 style="margin:4px 0">{e(f.title)}</h2>
        <p style="font-size:14px;word-wrap:break-word">{value}</p>
        {f'<p>{images}</p>' if images else ''}
        <table cellpadding="4">
        <tr><td style="color:#8b949e">Target</td><td>{e(str(f.target))}</td></tr>
        <tr><td style="color:#8b949e">Confidence</td><td>{int(f.confidence * 100)}%</td></tr>
        <tr><td style="color:#8b949e">Confirmed by</td><td>{e(', '.join(sorted(f.sources)))}</td></tr>
        </table>
        {f'<h4 style="color:{ACCENT}">Pivot from here</h4><ul>{pivots}</ul>' if pivots else ''}
        {f'<h4 style="color:#8b949e">Details</h4><pre style="color:#c9d1d9">{e(data)}</pre>' if data else ''}
        </div>""")

    def _welcome_html(self) -> str:
        cats = "".join(f"<li><b>{k}</b> - {', '.join(s.name for s in SOURCES if k in s.kinds)}</li>" for k in KINDS)
        return f"""<div style="font-family:Segoe UI;color:#e6edf3">
        <h2 style="color:{ACCENT}">◉ The all-seeing eye</h2>
        <p>Type anything - a username, email, phone, domain, IP, crypto wallet, profile URL, file path or a full name.
        For a deep dive, use <b>Full investigation…</b> and fill in everything you know.
        Panoptes detects what it is, runs every relevant source at once, merges duplicates, and follows
        what it discovers (emails → accounts → domains → IPs) up to the chosen depth.</p>
        <h4 style="color:#8b949e">Sources by target type</h4><ul>{cats}</ul>
        <p style="color:#8b949e">Double-click a result to open it · right-click to pivot or copy.</p></div>"""

    def _open_item(self, item: QTreeWidgetItem, _col: int):
        f = item.data(0, ROLE_FINDING)
        if f and f.url:
            QDesktopServices.openUrl(QUrl(f.url))

    def _tree_menu(self, pos):
        item = self.tree.itemAt(pos)
        f: Finding | None = item.data(0, ROLE_FINDING) if item else None
        if not f:
            return
        menu = QMenu(self)
        if f.url:
            menu.addAction("Open in browser", lambda: QDesktopServices.openUrl(QUrl(f.url)))
        menu.addAction("Copy value", lambda: QGuiApplication.clipboard().setText(f.value))
        from panoptes.sources import sources_for
        targets = list(f.pivots) or [parse_target(f.value)]
        for p in targets[:4]:
            menu.addAction(f"Search {p.kind}: {p.value[:40]} (add to this case)", lambda p=p: self.extend_case([p]))
            sub = menu.addMenu(f"Run transform on {p.value[:30]}")
            for src in sources_for(p.kind):
                sub.addAction(src.name, lambda p=p, s=src.name: self.extend_case([p], only={s}))
            menu.addAction(f"New search for {p.value[:40]}", lambda p=p: self._search_entity(p))
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def extend_case(self, entities: list[Entity], only: set[str] | None = None):
        """Maltego-style: run a search (or a single transform) on an entity and merge it into the open case."""
        if self.worker and self.worker.isRunning():
            self.pending.append((entities, only))
            self._on_log("info", f"Queued: {', '.join(map(str, entities))} - runs when the current search finishes")
            return
        if self.report is None:
            self._search_entity(entities[0])
            return
        options = SearchOptions(depth=0 if only else 1, scope=self.scope.currentText(), nsfw=self.nsfw.isChecked(),
                                verify=self.verify.isChecked())
        for key, act in self.cap_actions.items():
            setattr(options, key, act.isChecked())
        options.include = only or {n for n, a in self.source_actions.items() if a.isChecked() and a.isEnabled()}
        from panoptes.sources.base import apply_profile
        apply_profile(options, self.profile.currentText())
        self.bridge = Bridge()
        for sig, slot in ((self.bridge.entity, self._on_entity), (self.bridge.finding, self._on_finding),
                          (self.bridge.progress, self._on_progress), (self.bridge.source_start, self._on_source_start),
                          (self.bridge.source_done, self._on_source_done), (self.bridge.log, self._on_log)):
            sig.connect(slot)
        label = f"transform {', '.join(only)}" if only else "manual pivot"
        self.worker = SearchWorker(entities, options, self.bridge, report=self.report, via=f"{label} → {label}")
        self.worker.done.connect(self._on_done)
        self.search_btn.setEnabled(False)
        self.stop_btn.setVisible(True)
        self.started_at = time.time()
        self.timer.start(500)
        self._on_log("info", f"Extending case with {label}: {', '.join(map(str, entities))}")
        self.worker.start()

    def _on_link(self, url: QUrl):
        if url.scheme() == "panoptes":
            q = parse_qs(urlparse(url.toString()).query)
            self.extend_case([Entity(q["kind"][0], q["value"][0])])
        else:
            QDesktopServices.openUrl(url)

    def _search_entity(self, entity: Entity):
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, "Panoptes", "A search is already running.")
            return
        self.target.setText(entity.value)
        self.kind.setCurrentText(entity.kind if entity.kind in KINDS else "auto")
        self.start_search()

    # ---- tools
    def export(self, ext: str):
        if not self.report or not self.report.findings:
            QMessageBox.information(self, "Panoptes", "Run a search first.")
            return
        name = "panoptes_" + "_".join(t.value for t in self.report.targets)[:60]
        name = "".join(c if c.isalnum() or c in "._-@" else "_" for c in name)
        label = "STIX 2.1 bundle" if ext == "stix.json" else ext.upper()
        path, _ = QFileDialog.getSaveFileName(self, "Export report", f"{name}.{ext}", f"{label} (*.{ext})")
        if path:
            out = export(self.report, path)
            self.status_label.setText(f"Report saved: {out}")
            if ext == "html":
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(out)))

    def update_databases(self):
        if self.update_worker and self.update_worker.isRunning():
            return
        self.update_worker = UpdateWorker()
        self.update_worker.message.connect(lambda m: (self._on_log("info", m), self.status_label.setText(m)))
        self.update_worker.done.connect(self._update_done)
        self.status_label.setText("Updating site databases…")
        self.update_worker.start()

    def _update_done(self, result):
        if isinstance(result, Exception):
            QMessageBox.warning(self, "Update failed", str(result))
            return
        counts, stats = result
        rows = "".join(f"<tr><td>{db}</td><td align=right>{n}</td></tr>" for db, n in counts.items())
        merged = "".join(f"<tr><td>{s}</td><td align=right>{v['sites']}</td><td align=right>{v['multi_source']}</td></tr>"
                         for s, v in stats.items())
        QMessageBox.information(self, "Site databases updated",
                                f"<b>Raw databases</b><table>{rows}</table><br><b>Merged catalog</b>"
                                f"<table><tr><th>Scope</th><th>Sites</th><th>In 2+ DBs</th></tr>{merged}</table>")
        self.status_label.setText("Site databases updated")

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(5000)
        super().closeEvent(event)


def main(targets: list[str] | None = None):
    if targets is None:
        targets = sys.argv[1:]
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("panoptes.osint")
        except Exception:
            pass
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("Panoptes")
    app.setStyle("Fusion")
    pal = QPalette()
    for role, color in ((QPalette.Window, "#0d1117"), (QPalette.Base, "#161b22"), (QPalette.Text, "#e6edf3"),
                        (QPalette.WindowText, "#e6edf3"), (QPalette.Button, "#21262d"), (QPalette.ButtonText, "#e6edf3"),
                        (QPalette.Highlight, "#1f6feb"), (QPalette.ToolTipBase, "#161b22"), (QPalette.ToolTipText, "#e6edf3"),
                        (QPalette.Link, "#58a6ff")):
        pal.setColor(role, QColor(color))
    app.setPalette(pal)
    app.setStyleSheet(STYLE)
    app.setWindowIcon(eye_icon())
    win = MainWindow()
    win.show()
    if targets:
        win.target.setText(" ; ".join(targets))
        win.start_search()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
