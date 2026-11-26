"""Interactive link-analysis graph (Maltego-style) for the desktop app.

Nodes are entities (searched things) and findings; edges show how each was found. Drag nodes, click to
inspect, double-click to open/search, right-click for transforms that extend the current case.
"""
from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QAction, QBrush, QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (QGraphicsEllipseItem, QGraphicsItem, QGraphicsLineItem, QGraphicsScene,
                               QGraphicsSimpleTextItem, QGraphicsView, QHBoxLayout, QLabel, QLineEdit, QMenu,
                               QPushButton, QSpinBox, QToolButton, QVBoxLayout, QWidget)

from panoptes.models import Entity, Report

ACCENT = "#d4a017"
COLORS = {"username": "#3fb950", "email": "#d2a8ff", "domain": "#79c0ff", "ip": "#e3b341", "phone": "#58a6ff",
          "name": "#ffa657", "crypto": "#f778ba", "file": "#a5d6ff", "company": "#79c0ff", "location": "#e3b341",
          "onion": "#bc8cff", "bssid": "#e3b341", "account": "#2ea043", "alt-account": "#56d364", "breach": "#f85149",
          "profile": "#58a6ff", "alias": "#ffa657", "relationship": "#d2a8ff", "associate": "#79c0ff",
          "image-link": "#ffa657", "face-match": "#ff7b72", "image-match": "#a5d6ff", "web": "#8b949e", "news": "#8b949e",
          "record": "#d2a8ff", "threat": "#f85149", "darkweb": "#bc8cff", "subdomain": "#6e7681", "summary": ACCENT,
          "insight": "#f85149", "lookalike": "#f0883e", "related-domain": "#79c0ff", "wallet": "#f778ba", "geo": "#e3b341"}
DEFAULT_CATS = {"account", "alt-account", "email", "alias", "profile", "location", "breach", "relationship", "associate",
                "image-link", "face-match", "threat", "darkweb", "related-domain", "wallet", "phone", "record", "news"}
ALL_CATS = sorted(set(COLORS) - {"username", "domain", "ip", "name", "crypto", "file", "company", "onion", "bssid"}
                  | {"web", "subdomain", "lookalike", "image-match", "geo"})


def build_graph(report: Report, categories: set[str], max_nodes: int) -> tuple[list[dict], list[tuple[str, str, str]]]:
    nodes: dict[str, dict] = {}
    edges: list[tuple[str, str, str]] = []
    for ent, depth, via in report.entities.values():
        nodes[str(ent)] = {"id": str(ent), "label": ent.value if ent.kind != "file" else ent.value.replace("\\", "/").split("/")[-1],
                           "group": ent.kind, "entity": ent, "finding": None}
    for ent, depth, via in report.entities.values():
        if via:
            src = via.split(" → ")[0]
            if src in nodes:
                edges.append((src, str(ent), via.split(" → ", 1)[-1]))
    budget = max_nodes - len(nodes)
    ranked = sorted((f for f in report.findings.values() if f.category in categories and f.category not in ("summary", "insight")),
                    key=lambda f: (-f.confidence, f.category))
    per_target: dict[tuple, int] = {}
    for f in ranked:
        if budget <= 0:
            break
        piv = next((p for p in f.pivots if str(p) in nodes), None)
        if piv is not None:  # the pivot is already a node: draw an edge with the finding as label
            edges.append((str(f.target), str(piv), f.title))
            continue
        k = (str(f.target), f.category)
        if per_target.get(k, 0) >= 60:
            continue
        per_target[k] = per_target.get(k, 0) + 1
        nid = f"f:{hash(f.key())}"
        label = f.title if f.category in ("account", "breach") else f.value
        nodes[nid] = {"id": nid, "label": label[:42], "group": f.category, "entity": None, "finding": f}
        edges.append((f"hub:{k[0]}:{k[1]}", nid, ""))
        budget -= 1
    # Category hubs (entity -> "account (82)" -> accounts) keep big result sets readable.
    for (target, cat), n in per_target.items():
        hid = f"hub:{target}:{cat}"
        nodes[hid] = {"id": hid, "label": f"{cat} ({n})", "group": cat, "entity": None, "finding": None, "hub": True}
        edges.append((target, hid, cat))
    edges = [e for e in edges if e[0] in nodes and e[1] in nodes]
    return list(nodes.values()), edges


def layout(n: int, edges: list[tuple[int, int]], entity_mask: list[bool], iterations: int = 220,
           hub_mask: list[bool] | None = None):
    """Vectorised force-directed layout (fast enough for several hundred nodes)."""
    import numpy as np
    rng = np.random.default_rng(7)
    pos = rng.normal(0, 200, (n, 2))
    if n == 1:
        return pos
    ei = np.array(edges, dtype=int).reshape(-1, 2)
    ent = np.array(entity_mask)
    hub = np.array(hub_mask) if hub_mask is not None else np.zeros(n, bool)
    lengths = (np.where(ent[ei[:, 0]] & ent[ei[:, 1]], 260.0, np.where(hub[ei[:, 1]], 150.0, 55.0))
               if len(ei) else np.array([]))
    leaf = ~(ent | hub)
    charge = np.where(leaf, 0.35, 1.0)
    temp = 40.0
    for _ in range(iterations):
        delta = pos[:, None, :] - pos[None, :, :]
        d2 = (delta ** 2).sum(-1) + 0.01
        rep = (delta / d2[..., None]) * 2600 * (charge[:, None] * charge[None, :])[..., None]
        disp = rep.sum(1)
        if len(ei):
            vec = pos[ei[:, 1]] - pos[ei[:, 0]]
            dist = np.sqrt((vec ** 2).sum(1)) + 0.01
            force = ((dist - lengths) * 0.05)[:, None] * vec / dist[:, None]
            np.add.at(disp, ei[:, 0], force)
            np.add.at(disp, ei[:, 1], -force)
        disp -= pos * 0.004
        length = np.sqrt((disp ** 2).sum(1)) + 1e-9
        pos += disp / length[:, None] * np.minimum(length, temp)[:, None]
        temp = max(2.0, temp * 0.985)
    return pos


class Edge(QGraphicsLineItem):
    def __init__(self, a: "Node", b: "Node", label: str):
        super().__init__()
        self.a, self.b = a, b
        self.setPen(QPen(QColor("#30363d"), 1))
        self.setZValue(-1)
        if label:
            self.setToolTip(label)
        a.edges.append(self)
        b.edges.append(self)
        self.update_line()

    def update_line(self):
        self.setLine(self.a.scenePos().x(), self.a.scenePos().y(), self.b.scenePos().x(), self.b.scenePos().y())


class Node(QGraphicsEllipseItem):
    def __init__(self, data: dict, x: float, y: float):
        r = 16 if data["entity"] else 11 if data.get("hub") else 7
        super().__init__(-r, -r, 2 * r, 2 * r)
        self.data_ = data
        self.edges: list[Edge] = []
        self.setPos(x, y)
        self.setBrush(QBrush(QColor(COLORS.get(data["group"], "#8b949e"))))
        self.setPen(QPen(QColor(ACCENT), 2.5) if data["entity"] else QPen(Qt.NoPen))
        self.setFlags(QGraphicsItem.ItemIsSelectable | QGraphicsItem.ItemIgnoresTransformations)  # fixed size, not draggable
        self.setAcceptHoverEvents(True)
        self.setCursor(Qt.PointingHandCursor)
        f = data["finding"]
        tip = f"{data['group']}: {data['label']}"
        if f is not None:
            tip = f"{f.category} · {f.title}\n{f.value[:200]}\nconfidence {int(f.confidence * 100)}% · {', '.join(sorted(f.sources))}"
        self.setToolTip(tip)
        self.label = QGraphicsSimpleTextItem(data["label"], self)
        font = QFont()
        font.setPointSize(11 if data["entity"] else 9 if data.get("hub") else 7)
        font.setBold(bool(data["entity"] or data.get("hub")))
        self.label.setFont(font)
        self.label.setBrush(QColor("#e6edf3" if data["entity"] else "#9da7b3"))
        self.label.setPos(r + 3, -8)

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            for e in self.edges:
                e.update_line()
        return super().itemChange(change, value)

    def neighbours(self) -> set["Node"]:
        return {e.b if e.a is self else e.a for e in self.edges}


class GraphPanel(QWidget):
    node_selected = Signal(object)          # Finding or Entity
    search_entity = Signal(object)          # Entity -> extend the case with a full search
    run_transform = Signal(object, str)     # (Entity, source name) -> single transform

    def __init__(self, sources_for_kind):
        super().__init__()
        self.sources_for_kind = sources_for_kind
        self.report: Report | None = None
        self.categories = set(DEFAULT_CATS)
        self.nodes: list[Node] = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        bar = QHBoxLayout()
        cats = QToolButton()
        cats.setText("Show ▾")
        cats.setPopupMode(QToolButton.InstantPopup)
        menu = QMenu(self)
        for c in ALL_CATS:
            act = QAction(c, menu, checkable=True)
            act.setChecked(c in self.categories)
            act.toggled.connect(lambda on, c=c: (self.categories.add(c) if on else self.categories.discard(c), self.refresh()))
            menu.addAction(act)
        cats.setMenu(menu)
        bar.addWidget(cats)
        bar.addWidget(QLabel("Max nodes"))
        self.max_nodes = QSpinBox()
        self.max_nodes.setRange(20, 1500)
        self.max_nodes.setValue(350)
        self.max_nodes.setSingleStep(50)
        self.max_nodes.editingFinished.connect(self.refresh)
        bar.addWidget(self.max_nodes)
        self.find = QLineEdit()
        self.find.setPlaceholderText("highlight…")
        self.find.textChanged.connect(self._highlight)
        bar.addWidget(self.find, 1)
        for text, fn in (("Re-layout", self.refresh), ("Fit", self.fit)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            bar.addWidget(b)
        lay.addLayout(bar)
        self.view = QGraphicsView()
        self.view.setScene(QGraphicsScene(self))
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setDragMode(QGraphicsView.ScrollHandDrag)
        self.view.setBackgroundBrush(QColor("#0d1117"))
        self.view.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.view.wheelEvent = self._wheel
        self.view.mouseDoubleClickEvent = self._double
        self.view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self._menu)
        self.view.scene().selectionChanged.connect(self._selected)
        self.hint = QLabel("Scroll to zoom · drag the background to pan · click to inspect · double-click to open/search · right-click for transforms")
        self.hint.setStyleSheet("color:#8b949e;font-size:11px")
        lay.addWidget(self.view, 1)
        lay.addWidget(self.hint)

    # ---- rendering
    def render_report(self, report: Report | None):
        self.report = report
        self.refresh()

    def refresh(self):
        scene = self.view.scene()
        scene.clear()
        self.nodes = []
        if not self.report:
            return
        data, edges = build_graph(self.report, self.categories, self.max_nodes.value())
        if not data:
            return
        idx = {n["id"]: i for i, n in enumerate(data)}
        e_idx = [(idx[a], idx[b]) for a, b, _ in edges]
        pos = layout(len(data), e_idx, [n["entity"] is not None for n in data], hub_mask=[bool(n.get("hub")) for n in data])
        self.nodes = [Node(n, float(pos[i][0]), float(pos[i][1])) for i, n in enumerate(data)]
        for nd in self.nodes:
            scene.addItem(nd)
        for (a, b), (_, _, label) in zip(e_idx, edges):
            scene.addItem(Edge(self.nodes[a], self.nodes[b], label))
        self.hint.setText(f"{len(self.nodes)} nodes · {len(edges)} links · scroll to zoom · drag background to pan · "
                          f"click to inspect · double-click to open/search · right-click for transforms")
        self.fit()

    def fit(self):
        r = self.view.scene().itemsBoundingRect()
        if not r.isEmpty():
            self.view.fitInView(r.adjusted(-60, -60, 60, 60), Qt.KeepAspectRatio)
        self._labels()

    # ---- interaction
    def _wheel(self, event):
        f = 1.18 if event.angleDelta().y() > 0 else 1 / 1.18
        self.view.scale(f, f)
        self._labels()

    def _labels(self):
        """Entity and hub labels always; finding labels once zoomed in enough to read them."""
        zoomed = self.view.transform().m11() > 0.9
        for n in self.nodes:
            n.label.setVisible(bool(n.data_["entity"] or n.data_.get("hub")) or zoomed)

    def _node_at(self, pos) -> Node | None:
        item = self.view.itemAt(pos)
        while item is not None and not isinstance(item, Node):
            item = item.parentItem()
        return item

    def _selected(self):
        sel = [i for i in self.view.scene().selectedItems() if isinstance(i, Node)]
        near = set()
        for n in sel:
            near |= n.neighbours() | {n}
        for n in self.nodes:
            n.setOpacity(1.0 if not sel or n in near else 0.25)
        if sel:
            d = sel[0].data_
            self.node_selected.emit(d["finding"] if d["finding"] is not None else d["entity"])

    def _highlight(self, text: str):
        t = text.strip().lower()
        for n in self.nodes:
            hit = bool(t) and t in n.data_["label"].lower()
            n.setScale(1.8 if hit else 1.0)
            n.setOpacity(1.0 if not t or hit else 0.3)

    def _double(self, event):
        node = self._node_at(event.position().toPoint())
        if not node:
            return
        d = node.data_
        if d["entity"] is not None:
            self.search_entity.emit(d["entity"])
        elif d["finding"] is not None and d["finding"].url:
            from PySide6.QtCore import QUrl
            from PySide6.QtGui import QDesktopServices
            QDesktopServices.openUrl(QUrl(d["finding"].url))

    def _menu(self, pos):
        node = self._node_at(pos)
        if not node:
            return
        d = node.data_
        menu = QMenu(self)
        targets: list[Entity] = []
        if d["entity"] is not None:
            targets = [d["entity"]]
        elif d["finding"] is not None:
            targets = list(d["finding"].pivots)
            if d["finding"].url:
                from PySide6.QtCore import QUrl
                from PySide6.QtGui import QDesktopServices
                menu.addAction("Open link", lambda: QDesktopServices.openUrl(QUrl(d["finding"].url)))
        for ent in targets[:4]:
            menu.addAction(f"Search {ent.kind}: {ent.value[:40]} (add to case)", lambda e=ent: self.search_entity.emit(e))
            sub = menu.addMenu(f"Run transform on {ent.value[:30]}")
            for src in self.sources_for_kind(ent.kind):
                sub.addAction(src.name, lambda e=ent, s=src.name: self.run_transform.emit(e, s))
        menu.addSeparator()
        menu.addAction("Hide node", lambda: (node.setVisible(False), [e.setVisible(False) for e in node.edges]))
        menu.exec(self.view.viewport().mapToGlobal(pos))
