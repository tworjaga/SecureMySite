"""Reusable UI components for the SecureMySite GUI."""

import html
from typing import Dict, List, Optional, Sequence, Tuple

from PyQt6.QtCore import QEasingCurve, QRectF, QSize, Qt, QVariantAnimation, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont, QIcon, QPainter, QPen, QPixmap
from PyQt6.QtWidgets import (
    QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from core.insights import owasp_label
from gui.theme import Theme
from models.vulnerability import Severity, Vulnerability


def location_for(vulnerability: Vulnerability) -> str:
    """Project-relative location for display (falls back to absolute path / URL)."""
    rel = vulnerability.metadata.get('relative_path')
    if rel:
        return f"{rel}:{vulnerability.line_number}" if vulnerability.line_number else rel
    if vulnerability.file_path:
        return vulnerability.get_location_string()
    return vulnerability.metadata.get('url') or 'Web application'


_DOT_CACHE: Dict[str, QIcon] = {}


def severity_icon(severity_name: str) -> QIcon:
    """Small colored dot used in tables."""
    if severity_name not in _DOT_CACHE:
        pix = QPixmap(12, 12)
        pix.fill(Qt.GlobalColor.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(Theme.get_severity_color(severity_name)))
        p.drawEllipse(1, 1, 10, 10)
        p.end()
        _DOT_CACHE[severity_name] = QIcon(pix)
    return _DOT_CACHE[severity_name]


def section_label(text: str) -> QLabel:
    label = QLabel(text.upper())
    label.setObjectName("sectionLabel")
    return label


def card(title: Optional[str] = None) -> Tuple[QFrame, QVBoxLayout]:
    """A rounded surface with an optional title; returns (frame, content layout)."""
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(10)
    if title:
        heading = QLabel(title)
        heading.setObjectName("cardTitle")
        layout.addWidget(heading)
    return frame, layout


# --------------------------------------------------------------------------- score

class ScoreRing(QWidget):
    """Animated circular security score."""

    score_changed = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = 0.0
        self._target = 0
        self._grade = "-"
        self._risk = "Not scanned"
        self._has_result = False
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(1200)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._on_anim)
        self.setFixedSize(168, 168)

    def _on_anim(self, value):
        self._score = float(value)
        self.update()

    def set_score(self, score: int, risk_level: str, grade: str):
        self._target = max(0, min(100, int(score)))
        self._grade, self._risk, self._has_result = grade, risk_level, True
        self._anim.stop()
        self._anim.setStartValue(float(self._score))
        self._anim.setEndValue(float(self._target))
        self._anim.start()
        self.score_changed.emit(self._target)

    def reset(self):
        self._anim.stop()
        self._score, self._target, self._grade, self._risk, self._has_result = 0.0, 0, "-", "Not scanned", False
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect()).adjusted(10, 10, -10, -10)

        track = QPen(QColor(Theme.SURFACE_LIGHTER), 10)
        track.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(track)
        p.drawArc(rect, 0, 360 * 16)

        color = QColor(Theme.get_score_color(int(self._score)) if self._has_result else Theme.TEXT_DISABLED)
        if self._has_result:
            arc = QPen(color, 10)
            arc.setCapStyle(Qt.PenCapStyle.RoundCap)
            p.setPen(arc)
            span = max(2.0, self._score) * 3.6
            p.drawArc(rect, 90 * 16, int(-span * 16))

        p.setPen(QColor(Theme.TEXT_PRIMARY if self._has_result else Theme.TEXT_DISABLED))
        font = QFont(self.font())
        font.setPixelSize(40)
        font.setBold(True)
        p.setFont(font)
        number = str(int(round(self._score))) if self._has_result else "--"
        p.drawText(QRectF(rect.x(), rect.y() + 30, rect.width(), 50), Qt.AlignmentFlag.AlignCenter, number)

        font.setPixelSize(13)
        font.setBold(True)
        p.setFont(font)
        p.setPen(color)
        p.drawText(QRectF(rect.x(), rect.y() + 82, rect.width(), 20), Qt.AlignmentFlag.AlignCenter,
                   f"Grade {self._grade}" if self._has_result else "")
        font.setBold(False)
        font.setPixelSize(11)
        p.setFont(font)
        p.setPen(QColor(Theme.TEXT_TERTIARY))
        p.drawText(QRectF(rect.x(), rect.y() + 102, rect.width(), 18), Qt.AlignmentFlag.AlignCenter, self._risk)
        p.end()


# Backwards-compatible names
AnimatedScoreWidget = ScoreRing
ScoreDisplay = ScoreRing


class _MiniBar(QWidget):
    def __init__(self, color: str, parent=None):
        super().__init__(parent)
        self.color = QColor(color)
        self.fraction = 0.0
        self.setFixedHeight(6)

    def set_fraction(self, fraction: float):
        self.fraction = max(0.0, min(1.0, fraction))
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(Theme.SURFACE_LIGHTER))
        p.drawRoundedRect(QRectF(self.rect()), 3, 3)
        if self.fraction > 0:
            p.setBrush(self.color)
            w = max(6.0, self.width() * self.fraction)
            p.drawRoundedRect(QRectF(0, 0, w, self.height()), 3, 3)
        p.end()


class SeverityBadge(QWidget):
    """Severity row: colored name, proportional bar and count."""

    def __init__(self, severity: Severity, count: int = 0, parent=None):
        super().__init__(parent)
        self.severity = severity
        self.count = count
        color = Theme.get_severity_color(severity.name)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(4)

        top = QHBoxLayout()
        top.setSpacing(8)
        self.name_label = QLabel(severity.name.title())
        self.name_label.setStyleSheet(f"color: {color}; font-weight: 600; font-size: 12px;")
        self.count_label = QLabel(str(count))
        self.count_label.setStyleSheet(f"color: {Theme.TEXT_PRIMARY}; font-weight: 700; font-size: 12px;")
        self.count_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        top.addWidget(self.name_label)
        top.addStretch()
        top.addWidget(self.count_label)

        self.bar = _MiniBar(color)
        layout.addLayout(top)
        layout.addWidget(self.bar)

    def set_count(self, count: int, total: int = 0):
        self.count = count
        self.count_label.setText(str(count))
        self.bar.set_fraction(count / total if total else 0.0)


# --------------------------------------------------------------------------- stat card

class StatCard(QFrame):
    """KPI tile: title, big value, small hint."""

    def __init__(self, title: str, hint: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(2)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("cardTitle")
        self.value_label = QLabel("--")
        self.value_label.setStyleSheet(f"font-size: 24px; font-weight: 700; color: {Theme.TEXT_PRIMARY};")
        self.hint_label = QLabel(hint)
        self.hint_label.setObjectName("muted")
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.hint_label)

    def set_title(self, title: str):
        self.title_label.setText(title)

    def set_value(self, value, hint: Optional[str] = None, color: Optional[str] = None):
        self.value_label.setText(str(value))
        self.value_label.setStyleSheet(
            f"font-size: 24px; font-weight: 700; color: {color or Theme.TEXT_PRIMARY};")
        if hint is not None:
            self.hint_label.setText(hint)


# --------------------------------------------------------------------------- bar chart

class BarChart(QWidget):
    """Horizontal bar chart painted directly (label | bar | value)."""

    ROW_H = 28

    def __init__(self, empty_text: str = "No data", parent=None):
        super().__init__(parent)
        self.rows: List[Tuple[str, int, str]] = []
        self.empty_text = empty_text
        self.setMinimumHeight(self.ROW_H * 3)

    def set_rows(self, rows: Sequence[Tuple[str, int, str]]):
        """rows: (label, value, hex color)"""
        self.rows = list(rows)
        self.setMinimumHeight(max(self.ROW_H * 3, self.ROW_H * len(self.rows) + 4))
        self.updateGeometry()
        self.update()

    def sizeHint(self) -> QSize:
        return QSize(320, max(self.ROW_H * 3, self.ROW_H * len(self.rows) + 4))

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        font = QFont(self.font())
        font.setPixelSize(12)
        p.setFont(font)

        if not self.rows:
            p.setPen(QColor(Theme.TEXT_TERTIARY))
            p.drawText(QRectF(self.rect()), Qt.AlignmentFlag.AlignCenter, self.empty_text)
            p.end()
            return

        width = self.width()
        label_w = min(int(width * 0.48), 260)
        value_w = 36
        bar_x = label_w + 10
        bar_w = max(20, width - bar_x - value_w - 6)
        peak = max(v for _, v, _ in self.rows) or 1
        metrics = p.fontMetrics()

        for i, (label, value, color) in enumerate(self.rows):
            y = i * self.ROW_H + 2
            p.setPen(QColor(Theme.TEXT_SECONDARY))
            text = metrics.elidedText(label, Qt.TextElideMode.ElideMiddle, label_w)
            p.drawText(QRectF(0, y, label_w, self.ROW_H - 4),
                       Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, text)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(Theme.SURFACE_LIGHTER))
            bar_rect = QRectF(bar_x, y + (self.ROW_H - 4) / 2 - 4, bar_w, 8)
            p.drawRoundedRect(bar_rect, 4, 4)
            p.setBrush(QBrush(QColor(color)))
            p.drawRoundedRect(QRectF(bar_rect.x(), bar_rect.y(), max(8, bar_w * value / peak), 8), 4, 4)
            p.setPen(QColor(Theme.TEXT_PRIMARY))
            p.drawText(QRectF(width - value_w, y, value_w, self.ROW_H - 4),
                       Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, str(value))
        p.end()


# --------------------------------------------------------------------------- findings

class _FindingItem(QTreeWidgetItem):
    """Tree item that sorts the severity column by severity, not alphabetically."""

    def __lt__(self, other):
        column = self.treeWidget().sortColumn() if self.treeWidget() else 0
        if column == 0:
            a = self.data(0, Qt.ItemDataRole.UserRole)
            b = other.data(0, Qt.ItemDataRole.UserRole)
            return (a.severity.value, a.title) < (b.severity.value, b.title)
        return self.text(column).lower() < other.text(column).lower()


class VulnerabilityList(QWidget):
    """Filterable, sortable findings table."""

    vulnerability_selected = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.vulnerabilities: List[Vulnerability] = []
        self._filtered: List[Vulnerability] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        self.show_critical = self._chip("Critical", Theme.CRITICAL)
        self.show_high = self._chip("High", Theme.HIGH)
        self.show_medium = self._chip("Medium", Theme.MEDIUM)
        self.show_low = self._chip("Low", Theme.LOW)
        for chip in (self.show_critical, self.show_high, self.show_medium, self.show_low):
            toolbar.addWidget(chip)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search findings, files, CWE...  (Ctrl+F)")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._apply_filter)
        toolbar.addWidget(self.search_input, 1)

        self.count_label = QLabel("0 issues found")
        self.count_label.setObjectName("muted")
        toolbar.addWidget(self.count_label)
        layout.addLayout(toolbar)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["SEVERITY", "FINDING", "LOCATION", "SCANNER"])
        self.tree.setRootIsDecorated(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.setIconSize(QSize(10, 10))
        header = self.tree.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.setColumnWidth(0, 104)
        self.tree.setColumnWidth(2, 190)
        self.tree.currentItemChanged.connect(self._on_current_changed)
        layout.addWidget(self.tree, 1)

        # Older code/tests refer to the list widget by this name
        self.list_widget = self.tree

    def _chip(self, text: str, color: str) -> QPushButton:
        btn = QPushButton(text)
        btn.setCheckable(True)
        btn.setChecked(True)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent; color: {Theme.TEXT_TERTIARY};
                border: 1px solid {Theme.BORDER}; border-radius: 13px;
                padding: 4px 12px; font-size: 12px; font-weight: 600;
            }}
            QPushButton:checked {{
                background-color: {Theme.rgba(color, 14)}; color: {color};
                border: 1px solid {Theme.rgba(color, 45)};
            }}
            QPushButton:hover {{ border-color: {color}; }}
        """)
        btn.toggled.connect(self._apply_filter)
        return btn

    def set_vulnerabilities(self, vulnerabilities: List[Vulnerability]):
        self.vulnerabilities = list(vulnerabilities)
        self._apply_filter()

    def _apply_filter(self):
        show = set()
        for btn, sev in ((self.show_critical, Severity.CRITICAL), (self.show_high, Severity.HIGH),
                         (self.show_medium, Severity.MEDIUM), (self.show_low, Severity.LOW)):
            if btn.isChecked():
                show.add(sev)
        term = self.search_input.text().strip().lower()
        self._filtered = [
            v for v in self.vulnerabilities
            if v.severity in show and (not term or term in (
                f"{v.title} {location_for(v)} {v.description} {v.cwe_id or ''} {v.scanner_source}".lower()))
        ]

        self.tree.blockSignals(True)
        self.tree.setSortingEnabled(False)
        self.tree.clear()
        for vuln in self._filtered:
            item = _FindingItem([
                vuln.severity.name.title(), vuln.title, location_for(vuln), vuln.scanner_source.replace('_', ' ')
            ])
            item.setIcon(0, severity_icon(vuln.severity.name))
            item.setData(0, Qt.ItemDataRole.UserRole, vuln)
            item.setForeground(0, QBrush(QColor(Theme.get_severity_color(vuln.severity.name))))
            item.setForeground(2, QBrush(QColor(Theme.TEXT_SECONDARY)))
            item.setForeground(3, QBrush(QColor(Theme.TEXT_TERTIARY)))
            item.setToolTip(1, vuln.description)
            item.setToolTip(2, location_for(vuln))
            self.tree.addTopLevelItem(item)
        self.tree.setSortingEnabled(True)
        self.tree.blockSignals(False)

        self.count_label.setText(f"{len(self._filtered)} of {len(self.vulnerabilities)} issues")

    def _on_current_changed(self, current, _previous):
        if current is not None:
            self.vulnerability_selected.emit(current.data(0, Qt.ItemDataRole.UserRole))

    def select_row(self, row: int):
        item = self.tree.topLevelItem(row)
        if item:
            self.tree.setCurrentItem(item)
            self.tree.scrollToItem(item)

    def select_vulnerability(self, vulnerability: Vulnerability) -> bool:
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            if item.data(0, Qt.ItemDataRole.UserRole) is vulnerability:
                self.tree.setCurrentItem(item)
                self.tree.scrollToItem(item)
                return True
        return False

    def clear(self):
        self.vulnerabilities = []
        self._filtered = []
        self.tree.clear()
        self.count_label.setText("0 issues found")


# --------------------------------------------------------------------------- details

class DetailsView(QTextBrowser):
    """Rich, read-only finding details. All scanned content is HTML-escaped."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setOpenExternalLinks(True)
        self.document().setDocumentMargin(18)
        self.show_placeholder()

    def show_placeholder(self, text: str = "Select a finding to see details, the vulnerable code and how to fix it."):
        self.setHtml(f'<p style="color:{Theme.TEXT_TERTIARY}; font-size:13px;">{html.escape(text)}</p>')

    def show_vulnerability(self, v: Vulnerability):
        e = html.escape
        color = Theme.get_severity_color(v.severity.name)
        pill = (f'<span style="background-color:{color}; color:{Theme.BACKGROUND}; font-weight:700;'
                f' font-size:11px;">&nbsp;{v.severity.name}&nbsp;</span>')
        meta = [e(location_for(v)), e(v.scanner_source.replace('_', ' ')), e(owasp_label(v))]
        if v.cwe_id:
            num = e(v.cwe_id.split('-')[-1])
            meta.append(f'<a style="color:{Theme.PRIMARY};" href="https://cwe.mitre.org/data/definitions/{num}.html">'
                        f'{e(v.cwe_id)}</a>')

        code_html = ''
        if v.code_snippet:
            rows = []
            for line in v.code_snippet.splitlines():
                flagged = line.startswith('>>>')
                bg = Theme.rgba(color, 16) if flagged else 'transparent'
                fg = Theme.TEXT_PRIMARY if flagged else Theme.TEXT_SECONDARY
                rows.append(f'<tr><td style="background-color:{bg}; color:{fg}; padding:1px 8px;">'
                            f'<pre style="margin:0; font-family:Consolas, monospace; font-size:12px;">'
                            f'{e(line)}</pre></td></tr>')
            label = 'VULNERABLE CODE' if v.file_path else 'EVIDENCE'
            code_html = (f'<p style="color:{Theme.TEXT_TERTIARY}; font-size:11px; font-weight:700;">{label}</p>'
                         f'<table width="100%" cellspacing="0" style="background-color:{Theme.SURFACE_DARK};">'
                         + ''.join(rows) + '</table>')

        extra = ''
        if v.metadata.get('fixed_version'):
            extra += f'<p><b>Fixed in:</b> {e(str(v.metadata["fixed_version"]))}</p>'
        if v.metadata.get('advisories'):
            extra += f'<p><b>Advisories:</b> {e(", ".join(v.metadata["advisories"][:15]))}</p>'

        self.setHtml(f"""
            <div style="font-size:13px; color:{Theme.TEXT_PRIMARY};">
            <p>{pill}</p>
            <p style="font-size:17px; font-weight:700; margin-top:6px;">{e(v.title)}</p>
            <p style="color:{Theme.TEXT_TERTIARY}; font-size:12px;">{' &nbsp;&middot;&nbsp; '.join(meta)}</p>
            <p style="color:{Theme.TEXT_TERTIARY}; font-size:11px; font-weight:700; margin-top:14px;">WHY IT MATTERS</p>
            <p style="color:{Theme.TEXT_SECONDARY};">{e(v.description)}</p>
            <p style="color:{Theme.TEXT_TERTIARY}; font-size:11px; font-weight:700; margin-top:14px;">HOW TO FIX</p>
            <p style="color:{Theme.SUCCESS};">{e(v.remediation)}</p>
            {extra}
            {code_html}
            </div>
        """)


# --------------------------------------------------------------------------- tables

def make_table(headers: Sequence[str]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels([h.upper() for h in headers])
    table.verticalHeader().setVisible(False)
    table.setShowGrid(False)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setSortingEnabled(True)
    table.setWordWrap(False)
    table.horizontalHeader().setHighlightSections(False)
    table.horizontalHeader().setStretchLastSection(True)
    table.verticalHeader().setDefaultSectionSize(32)
    return table


def fill_table(table: QTableWidget, rows: Sequence[Tuple[Severity, Sequence[str], object]]):
    """rows: (severity, cell texts after the severity column, payload stored on the row)."""
    table.setSortingEnabled(False)
    table.setRowCount(0)
    for severity, cells, payload in rows:
        r = table.rowCount()
        table.insertRow(r)
        sev_item = QTableWidgetItem(severity.name.title())
        sev_item.setIcon(severity_icon(severity.name))
        sev_item.setForeground(QBrush(QColor(Theme.get_severity_color(severity.name))))
        sev_item.setData(Qt.ItemDataRole.UserRole, payload)
        table.setItem(r, 0, sev_item)
        for c, text in enumerate(cells, start=1):
            item = QTableWidgetItem(str(text))
            item.setToolTip(str(text))
            table.setItem(r, c, item)
    table.resizeColumnsToContents()
    for c in range(table.columnCount() - 1):
        table.setColumnWidth(c, min(table.columnWidth(c) + 16, 320))
    table.setSortingEnabled(False)  # keep critical-first order from the engine
