"""Primary application window for SecureMySite."""

import html
import re
import logging
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings, QUrl
from PyQt6.QtGui import QAction, QKeySequence, QDesktopServices, QShortcut
from PyQt6.QtWidgets import (
    QApplication, QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFrame,
    QGridLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSplitter, QStackedWidget,
    QStatusBar, QTabWidget, QTextBrowser, QToolButton, QVBoxLayout, QWidget,
)

from core import reporter
from core.config import APP_VERSION, Config
from core.engine import AnalysisEngine
from core.insights import build_insights
from scanners.domain_scanner import DomainScanner
from gui.components import (
    BarChart, DetailsView, ScoreRing, SeverityBadge, StatCard, VulnerabilityList,
    card, fill_table, location_for, make_table, section_label, severity_icon,
)
from gui.theme import Theme
from models.scan_result import ScanResult
from models.vulnerability import Severity, Vulnerability
from prompt_engine.prompt_builder import PromptBuilder
from utils.validators import normalize_domain, validate_project_path, validate_url


class ScanWorker(QThread):
    """Background worker for security scanning."""

    finished = pyqtSignal(object)  # ScanResult
    error = pyqtSignal(str)
    progress = pyqtSignal(str)
    file_progress = pyqtSignal(int, int)  # current, total

    def __init__(self, project_path: Optional[Path], url: Optional[str] = None,
                 scanner_config: Optional[dict] = None, domain: Optional[str] = None,
                 active: bool = False):
        super().__init__()
        self.project_path = project_path
        self.url = url
        self.scanner_config = scanner_config or {}
        self.domain = domain
        self.active = active
        self.engine = None

    def cancel(self):
        """Ask the engine to stop after the current file / step."""
        if self.engine:
            self.engine.cancel()

    def _on_progress(self, message: str, current: int, total: int):
        self.progress.emit(message)
        if total:
            self.file_progress.emit(current, total)

    def run(self):
        try:
            self.progress.emit("Initializing scanners...")
            if self.domain:
                self.engine = DomainScanner(active=self.active)
                result = self.engine.scan(self.domain, progress=self._on_progress)
            else:
                self.engine = AnalysisEngine(self.project_path, scanner_config=self.scanner_config)
                result = self.engine.analyze(self.url, progress=self._on_progress)
            self.progress.emit("Complete")
            self.finished.emit(result)
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            self.error.emit(str(e))


class TextDialog(QDialog):
    """Read-only text viewer with Copy and Save buttons (used for AI prompts)."""

    def __init__(self, parent: QWidget, title: str, text: str, default_name: str = "prompt.md"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(860, 620)
        self._default_name = default_name

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        heading = QLabel(title)
        heading.setStyleSheet("font-size: 16px; font-weight: 700;")
        hint = QLabel("Copied to clipboard - paste it into ChatGPT, Claude or your coding assistant.")
        hint.setObjectName("muted")
        layout.addWidget(heading)
        layout.addWidget(hint)

        self.editor = QPlainTextEdit()
        self.editor.setPlainText(text)
        self.editor.setReadOnly(True)
        self.editor.setStyleSheet(f"font-family: {Theme.FONT_MONO}; font-size: 12px; padding: 8px;")
        layout.addWidget(self.editor)

        buttons = QDialogButtonBox()
        copy_btn = buttons.addButton("Copy", QDialogButtonBox.ButtonRole.ActionRole)
        save_btn = buttons.addButton("Save...", QDialogButtonBox.ButtonRole.ActionRole)
        buttons.addButton(QDialogButtonBox.StandardButton.Close)
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.editor.toPlainText()))
        save_btn.clicked.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _save(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save", self._default_name, "Markdown (*.md);;Text (*.txt)")
        if path:
            Path(path).write_text(self.editor.toPlainText(), encoding="utf-8")


class MainWindow(QMainWindow):
    """Primary application window: sidebar with controls, dashboard with tabs."""

    SEVERITY_FILTERS = [None, "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{Config.GUI_WINDOW_TITLE} {APP_VERSION}")
        self.setMinimumSize(1100, 700)
        self.resize(1360, 880)

        self.current_result: Optional[ScanResult] = None
        self.scan_worker: Optional[ScanWorker] = None
        self.selected_vulnerability: Optional[Vulnerability] = None
        self._text_dialog: Optional[TextDialog] = None
        self.settings = QSettings("SecureMySite", "App")
        self.setAcceptDrops(True)

        self.setStyleSheet(Theme.get_stylesheet())
        self._setup_menu()
        self._setup_ui()
        self._setup_shortcuts()
        self._load_settings()

    # ================================================================ layout

    def _setup_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")

        open_action = QAction("Open Project...", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self._browse_project)
        file_menu.addAction(open_action)

        scan_action = QAction("Run Scan", self)
        scan_action.setShortcut(QKeySequence("Ctrl+R"))
        scan_action.triggered.connect(self._start_scan)
        file_menu.addAction(scan_action)
        file_menu.addSeparator()

        self.export_menu = QMenu("Export", self)
        for label, fmt in (("HTML report...", "html"), ("Markdown...", "markdown"), ("JSON...", "json"),
                           ("SARIF (GitHub code scanning)...", "sarif"), ("CSV...", "csv")):
            action = QAction(label, self)
            action.triggered.connect(lambda _=False, f=fmt: self._export_results(f))
            self.export_menu.addAction(action)
        self.export_menu.addSeparator()
        baseline_action = QAction("Save as Baseline...", self)
        baseline_action.triggered.connect(lambda: self._export_results("json", baseline=True))
        self.export_menu.addAction(baseline_action)
        file_menu.addMenu(self.export_menu)
        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        help_menu = menubar.addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+F"), self, activated=self._focus_search)

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._create_sidebar())
        root.addWidget(self._create_main_area(), 1)

        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Ready - choose a project folder or drop one onto the window")

    # ---------------------------------------------------------------- sidebar

    def _create_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(320)
        outer = QVBoxLayout(sidebar)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        content = QWidget()
        scroll.setWidget(content)
        layout = QVBoxLayout(content)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(10)

        # Brand
        brand = QLabel("SecureMySite")
        brand.setStyleSheet("font-size: 20px; font-weight: 800;")
        tagline = QLabel(f"v{APP_VERSION}  ·  local security analyzer")
        tagline.setObjectName("muted")
        layout.addWidget(brand)
        layout.addWidget(tagline)
        layout.addSpacing(8)

        # Mode switch
        mode_row = QHBoxLayout()
        mode_row.setSpacing(0)
        self.mode_group = QButtonGroup(self)
        self.project_mode_btn = QPushButton("Project")
        self.domain_mode_btn = QPushButton("Domain")
        for i, btn in enumerate((self.project_mode_btn, self.domain_mode_btn)):
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setMinimumHeight(34)
            radius = "border-top-left-radius: 8px; border-bottom-left-radius: 8px;" if i == 0 else \
                "border-top-right-radius: 8px; border-bottom-right-radius: 8px;"
            btn.setStyleSheet(f"""
                QPushButton {{ background: {Theme.SURFACE_DARK}; color: {Theme.TEXT_TERTIARY};
                               border: 1px solid {Theme.BORDER}; border-radius: 0; {radius} font-weight: 600; }}
                QPushButton:checked {{ background: {Theme.rgba(Theme.PRIMARY, 18)}; color: {Theme.TEXT_PRIMARY};
                                       border-color: {Theme.PRIMARY}; }}
            """)
            self.mode_group.addButton(btn, i)
            mode_row.addWidget(btn)
        self.project_mode_btn.setChecked(True)
        self.mode_group.idToggled.connect(lambda _id, checked: checked and self._on_mode_changed())
        layout.addLayout(mode_row)
        layout.addSpacing(4)

        self.mode_stack = QStackedWidget()
        self.mode_stack.addWidget(self._create_project_panel())
        self.mode_stack.addWidget(self._create_domain_panel())
        layout.addWidget(self.mode_stack)

        self.scan_btn = QPushButton("Start Security Analysis")
        self.scan_btn.setObjectName("primaryButton")
        self.scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_btn.setMinimumHeight(42)
        self.scan_btn.clicked.connect(self._start_scan)
        layout.addWidget(self.scan_btn)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.hide()
        self.progress_label = QLabel("")
        self.progress_label.setObjectName("muted")
        self.progress_label.hide()
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.progress_label)
        layout.addSpacing(10)

        # Score
        layout.addWidget(section_label("Security score"))
        self.score_display = ScoreRing()
        ring_row = QHBoxLayout()
        ring_row.addStretch()
        ring_row.addWidget(self.score_display)
        ring_row.addStretch()
        layout.addLayout(ring_row)

        self.critical_badge = SeverityBadge(Severity.CRITICAL)
        self.high_badge = SeverityBadge(Severity.HIGH)
        self.medium_badge = SeverityBadge(Severity.MEDIUM)
        self.low_badge = SeverityBadge(Severity.LOW)
        for badge in (self.critical_badge, self.high_badge, self.medium_badge, self.low_badge):
            layout.addWidget(badge)
        layout.addSpacing(10)

        layout.addStretch()
        return sidebar

    def _create_project_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        layout.addWidget(section_label("Project folder"))
        path_row = QHBoxLayout()
        path_row.setSpacing(6)
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Folder to scan")
        self.path_input.returnPressed.connect(self._start_scan)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self._browse_project)
        path_row.addWidget(self.path_input, 1)
        path_row.addWidget(browse_btn)
        layout.addLayout(path_row)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://localhost:8000  (optional live scan)")
        self.url_input.textChanged.connect(self._validate_url_live)
        layout.addWidget(self.url_input)
        self.url_hint = QLabel("")
        self.url_hint.setObjectName("muted")
        self.url_hint.setWordWrap(True)
        self.url_hint.hide()
        layout.addWidget(self.url_hint)
        layout.addSpacing(4)

        layout.addWidget(section_label("Options"))
        self.min_severity_combo = QComboBox()
        self.min_severity_combo.addItems(["Show all severities", "Low and above", "Medium and above",
                                          "High and above", "Critical only"])
        layout.addWidget(self.min_severity_combo)
        self.online_check = QCheckBox("Online CVE lookup (OSV.dev)")
        self.online_check.setToolTip(
            "Sends package names and versions to api.osv.dev to find vulnerabilities newer than the "
            "bundled database. Off by default - everything else stays on your machine.")
        self.baseline_check = QCheckBox("Only new since baseline")
        self.baseline_check.setToolTip("Hide findings recorded with File > Export > Save as Baseline")
        layout.addWidget(self.online_check)
        layout.addWidget(self.baseline_check)
        layout.addSpacing(6)
        return panel

    def _create_domain_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        layout.addWidget(section_label("Domain"))
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        self.domain_input.returnPressed.connect(self._start_scan)
        self.domain_input.textChanged.connect(self._validate_domain_live)
        layout.addWidget(self.domain_input)
        self.domain_hint = QLabel("")
        self.domain_hint.setObjectName("muted")
        self.domain_hint.setWordWrap(True)
        self.domain_hint.hide()
        layout.addWidget(self.domain_hint)

        checks = QLabel("DNS & DNSSEC  ·  SPF / DMARC  ·  WHOIS  ·  TLS  ·  headers, cookies, CORS  ·  CDN / WAF")
        checks.setWordWrap(True)
        checks.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px;")
        layout.addWidget(checks)
        note = QLabel("Online scan: uses Cloudflare DNS-over-HTTPS and rdap.org, and connects to the site "
                      "like a browser would.")
        note.setWordWrap(True)
        note.setObjectName("muted")
        layout.addWidget(note)
        layout.addSpacing(4)

        layout.addWidget(section_label("Active checks"))
        self.authorized_check = QCheckBox("I own this domain or am authorized to test it")
        self.active_check = QCheckBox("Probe for exposed files (/.env, /.git, backups)")
        self.active_check.setEnabled(False)
        self.authorized_check.toggled.connect(self._on_authorized_toggled)
        for check in (self.authorized_check, self.active_check):
            check.setStyleSheet("QCheckBox { font-size: 12px; }")
            layout.addWidget(check)
        layout.addSpacing(6)
        return panel

    def _on_authorized_toggled(self, checked: bool):
        self.active_check.setEnabled(checked)
        if not checked:
            self.active_check.setChecked(False)

    def _validate_domain_live(self, text: str):
        if not text.strip():
            self.domain_input.setStyleSheet("")
            self.domain_hint.hide()
            return
        host, error = normalize_domain(text)
        self.domain_input.setStyleSheet("" if host else f"QLineEdit {{ border-color: {Theme.CRITICAL}; }}")
        self.domain_hint.setText(error or "")
        self.domain_hint.setVisible(not host)

    def _is_domain_mode(self) -> bool:
        return self.domain_mode_btn.isChecked()

    def _on_mode_changed(self):
        self.mode_stack.setCurrentIndex(1 if self._is_domain_mode() else 0)
        self.scan_btn.setText(self._idle_scan_text())
        (self.domain_input if self._is_domain_mode() else self.path_input).setFocus()

    def _idle_scan_text(self) -> str:
        return "Scan Domain" if self._is_domain_mode() else "Start Security Analysis"

    # ---------------------------------------------------------------- main area

    def _create_main_area(self) -> QWidget:
        main = QWidget()
        layout = QVBoxLayout(main)
        layout.setContentsMargins(24, 18, 24, 12)
        layout.setSpacing(14)

        header = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(2)
        self.project_title = QLabel("No project scanned yet")
        self.project_title.setStyleSheet("font-size: 20px; font-weight: 700;")
        self.project_title.setTextFormat(Qt.TextFormat.PlainText)
        self.project_subtitle = QLabel("Static analysis, secrets, dependencies, infrastructure and live checks")
        self.project_subtitle.setObjectName("muted")
        self.project_subtitle.setTextFormat(Qt.TextFormat.PlainText)
        titles.addWidget(self.project_title)
        titles.addWidget(self.project_subtitle)
        header.addLayout(titles, 1)

        self.prompt_btn = QPushButton("AI Fix Prompt")
        self.prompt_btn.setToolTip("Build a prompt covering every finding (copied to clipboard)")
        self.prompt_btn.clicked.connect(self._generate_prompt)
        self.copy_btn = QPushButton("Copy Summary")
        self.copy_btn.clicked.connect(self._copy_results)
        self.export_btn = QToolButton()
        self.export_btn.setText("Export  ▾")
        self.export_btn.setMenu(self.export_menu)
        self.export_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        for btn in (self.prompt_btn, self.copy_btn, self.export_btn):
            btn.setEnabled(False)
            btn.setMinimumHeight(34)
            header.addWidget(btn, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(header)

        # KPI cards
        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.stat_findings = StatCard("Findings", "after de-duplication")
        self.stat_secrets = StatCard("Exposed secrets", "keys, tokens, passwords")
        self.stat_injection = StatCard("Injection risks", "SQLi, XSS, RCE, SSTI")
        self.stat_packages = StatCard("Vulnerable packages", "known CVEs")
        self.stat_files = StatCard("Files scanned", "")
        for c in (self.stat_findings, self.stat_secrets, self.stat_injection, self.stat_packages, self.stat_files):
            cards.addWidget(c, 1)
        layout.addLayout(cards)

        # Empty state vs. results
        self.stack = QStackedWidget()
        self.stack.addWidget(self._create_empty_state())
        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_findings_tab(), "Findings")
        self.domain_tab = self._create_domain_tab()
        self.tabs.addTab(self.domain_tab, "Domain Profile")
        self.tabs.addTab(self._create_overview_tab(), "Overview")
        self.deps_tab = self._create_dependencies_tab()
        self.tabs.addTab(self.deps_tab, "Dependencies")
        self.secrets_tab = self._create_secrets_tab()
        self.tabs.addTab(self.secrets_tab, "Secrets")
        self.tabs.addTab(self._create_scan_info_tab(), "Scan Info")
        self.tabs.setTabVisible(self.tabs.indexOf(self.domain_tab), False)
        self.stack.addWidget(self.tabs)
        layout.addWidget(self.stack, 1)
        return main

    def _create_empty_state(self) -> QWidget:
        frame, layout = card()
        layout.setContentsMargins(40, 40, 40, 40)
        layout.addStretch()
        title = QLabel("Scan a project to see its security posture")
        title.setStyleSheet("font-size: 18px; font-weight: 700;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint = QLabel("Pick a folder in the sidebar or drag it onto this window, then press Start.")
        hint.setObjectName("muted")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        layout.addWidget(hint)
        layout.addSpacing(18)

        grid = QGridLayout()
        grid.setHorizontalSpacing(28)
        grid.setVerticalSpacing(10)
        checks = [
            ("Code", "SQL/command injection, XSS, SSTI, eval, unsafe deserialization"),
            ("Secrets", "AWS, GitHub, Stripe, OpenAI, Anthropic keys, private keys, .env files"),
            ("Dependencies", "Known CVEs in requirements, pyproject, package.json, lockfiles"),
            ("Infrastructure", "Dockerfile, docker-compose and GitHub Actions misconfigurations"),
            ("Live app", "Headers, cookies, CORS, exposed /.env and /.git on localhost"),
        ]
        for row, (name, text) in enumerate(checks):
            n = QLabel(name)
            n.setStyleSheet(f"color: {Theme.PRIMARY}; font-weight: 700;")
            t = QLabel(text)
            t.setStyleSheet(f"color: {Theme.TEXT_SECONDARY};")
            grid.addWidget(n, row, 0)
            grid.addWidget(t, row, 1)
        wrapper = QHBoxLayout()
        wrapper.addStretch()
        wrapper.addLayout(grid)
        wrapper.addStretch()
        layout.addLayout(wrapper)
        layout.addStretch()
        return frame

    def _create_findings_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 12, 0, 0)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        self.vuln_list = VulnerabilityList()
        self.vuln_list.vulnerability_selected.connect(self._on_vulnerability_selected)
        self.vuln_list.setMinimumWidth(460)
        splitter.addWidget(self.vuln_list)

        details = QWidget()
        details_layout = QVBoxLayout(details)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.setSpacing(8)
        self.details_view = DetailsView()
        details_layout.addWidget(self.details_view, 1)

        actions = QHBoxLayout()
        actions.setSpacing(6)
        self.quick_prompt_btn = QPushButton("AI Prompt")
        self.quick_prompt_btn.setToolTip("Prompt for this finding only")
        self.quick_prompt_btn.clicked.connect(self._quick_fix_prompt)
        self.open_file_btn = QPushButton("Open")
        self.open_file_btn.clicked.connect(self._open_selected_file)
        self.copy_location_btn = QPushButton("Copy Path")
        self.copy_location_btn.clicked.connect(self._copy_location)
        self.cwe_btn = QPushButton("CWE")
        self.cwe_btn.clicked.connect(self._open_cwe)
        for btn in (self.quick_prompt_btn, self.open_file_btn, self.copy_location_btn, self.cwe_btn):
            btn.setEnabled(False)
            actions.addWidget(btn)
        actions.addStretch()
        details_layout.addLayout(actions)

        details.setMinimumWidth(360)
        splitter.addWidget(details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter)
        return page

    def _create_overview_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        page = QWidget()
        scroll.setWidget(page)
        grid = QGridLayout(page)
        grid.setContentsMargins(0, 12, 0, 0)
        grid.setSpacing(12)

        owasp_card, owasp_layout = card("OWASP Top 10 (2021) coverage")
        self.owasp_chart = BarChart("No OWASP-mapped findings")
        owasp_layout.addWidget(self.owasp_chart)
        owasp_layout.addStretch()

        hotspot_card, hotspot_layout = card("Riskiest files (weighted by severity)")
        self.hotspot_chart = BarChart("No file-level findings")
        hotspot_layout.addWidget(self.hotspot_chart)
        hotspot_layout.addStretch()

        category_card, category_layout = card("Findings by category")
        self.category_chart = BarChart()
        category_layout.addWidget(self.category_chart)
        self.scanner_chart_label = QLabel("By scanner")
        self.scanner_chart_label.setObjectName("cardTitle")
        category_layout.addWidget(self.scanner_chart_label)
        self.scanner_chart = BarChart()
        category_layout.addWidget(self.scanner_chart)
        category_layout.addStretch()

        fix_card, fix_layout = card("Fix these first  (double-click to open)")
        self.fix_first_list = QListWidget()
        self.fix_first_list.setStyleSheet(
            f"QListWidget {{ border: none; background: transparent; }}"
            f"QListWidget::item {{ padding: 8px 6px; border-bottom: 1px solid {Theme.BORDER}; }}"
            f"QListWidget::item:selected {{ background: {Theme.rgba(Theme.PRIMARY, 18)}; }}")
        self.fix_first_list.itemDoubleClicked.connect(
            lambda item: self._jump_to(item.data(Qt.ItemDataRole.UserRole)))
        self.fix_first_list.setMinimumHeight(300)
        fix_layout.addWidget(self.fix_first_list)
        self.recommendations_label = QLabel("")
        self.recommendations_label.setWordWrap(True)
        self.recommendations_label.setObjectName("muted")
        self.recommendations_label.setTextFormat(Qt.TextFormat.PlainText)
        fix_layout.addWidget(self.recommendations_label)

        grid.addWidget(owasp_card, 0, 0)
        grid.addWidget(fix_card, 0, 1)
        grid.addWidget(hotspot_card, 1, 0)
        grid.addWidget(category_card, 1, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setRowStretch(2, 1)
        return scroll

    def _create_dependencies_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 12, 0, 0)
        self.deps_hint = QLabel("")
        self.deps_hint.setObjectName("muted")
        layout.addWidget(self.deps_hint)
        self.deps_table = make_table(["Severity", "Package", "Version", "Advisory", "Fixed in", "Location"])
        self.deps_table.cellDoubleClicked.connect(lambda r, _c: self._jump_from_table(self.deps_table, r))
        layout.addWidget(self.deps_table)
        return page

    def _create_secrets_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 12, 0, 0)
        hint = QLabel("Values are masked. Rotate every exposed credential - deleting it from the code is not enough "
                      "once it has been committed or deployed.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.secrets_table = make_table(["Severity", "Type", "Location", "Value (masked)"])
        self.secrets_table.cellDoubleClicked.connect(lambda r, _c: self._jump_from_table(self.secrets_table, r))
        layout.addWidget(self.secrets_table)
        return page

    def _create_domain_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 12, 0, 0)
        self.domain_view = QTextBrowser()
        self.domain_view.setOpenExternalLinks(False)
        self.domain_view.document().setDocumentMargin(18)
        layout.addWidget(self.domain_view)
        return page

    def _create_scan_info_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 12, 0, 0)
        self.scan_info = QTextBrowser()
        self.scan_info.setOpenExternalLinks(False)
        self.scan_info.document().setDocumentMargin(18)
        layout.addWidget(self.scan_info)
        return page

    # ================================================================ settings & inputs

    def _load_settings(self):
        last_path = self.settings.value("last_project_path", "")
        if last_path:
            self.path_input.setText(last_path)
        last_domain = self.settings.value("last_domain", "")
        if last_domain:
            self.domain_input.setText(last_domain)

    def _save_settings(self):
        self.settings.setValue("last_project_path", self.path_input.text())
        self.settings.setValue("last_domain", self.domain_input.text())

    def _browse_project(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select Project Directory", self.path_input.text() or str(Path.home()))
        if path:
            self.path_input.setText(path)
            self._save_settings()

    def _validate_url_live(self, text: str):
        text = text.strip()
        if not text:
            self.url_input.setStyleSheet("")
            self.url_hint.hide()
            return
        ok, error = validate_url(text)
        self.url_input.setStyleSheet("" if ok else f"QLineEdit {{ border-color: {Theme.CRITICAL}; }}")
        self.url_hint.setText(error or "")
        self.url_hint.setVisible(not ok)

    def _validate_url(self):
        """Kept for compatibility: validate the URL field and report the result."""
        url = self.url_input.text().strip()
        if not url:
            return True
        ok, error = validate_url(url)
        if not ok:
            QMessageBox.warning(self, "Invalid URL", error)
        return ok

    def _focus_search(self):
        self.tabs.setCurrentIndex(0)
        self.vuln_list.search_input.setFocus()
        self.vuln_list.search_input.selectAll()

    # ================================================================ scanning

    def _baseline_path(self, project_path: Path) -> Path:
        return Path(project_path) / ".securemysite-baseline.json"

    def _start_scan(self):
        """Start a scan, or cancel the running one."""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.cancel()
            self.scan_btn.setEnabled(False)
            self.statusbar.showMessage("Cancelling...")
            return

        if self._is_domain_mode():
            host, error = normalize_domain(self.domain_input.text())
            if not host:
                QMessageBox.warning(self, "Invalid Domain", error)
                return
            self._begin_scan(ScanWorker(None, domain=host,
                                        active=self.authorized_check.isChecked() and self.active_check.isChecked()))
            return

        path_text = self.path_input.text().strip()
        if not path_text:
            QMessageBox.warning(self, "No Project", "Choose a project directory first.")
            return
        ok, error = validate_project_path(path_text)
        if not ok:
            QMessageBox.warning(self, "Invalid Path", error)
            return

        url = self.url_input.text().strip() or None
        if url and not self._validate_url():
            return

        self._run_scan(Path(path_text), url)

    def _run_scan(self, project_path: Path, url: Optional[str]):
        scanner_config = {
            "min_severity": self.SEVERITY_FILTERS[self.min_severity_combo.currentIndex()],
            "dependency_scanner": {"online": self.online_check.isChecked()},
        }
        if self.baseline_check.isChecked():
            baseline = self._baseline_path(project_path)
            if baseline.is_file():
                scanner_config["baseline"] = str(baseline)
            else:
                QMessageBox.information(self, "No Baseline",
                                        "No baseline saved for this project yet. "
                                        "Use File > Export > Save as Baseline after a scan.")

        self._begin_scan(ScanWorker(project_path, url, scanner_config))

    def _begin_scan(self, worker: "ScanWorker"):
        self.scan_btn.setText("Cancel Scan")
        self._set_button_role(self.scan_btn, "dangerButton")
        self.progress_bar.setRange(0, 0)
        self.progress_bar.show()
        self.progress_label.setText("Starting...")
        self.progress_label.show()
        self.statusbar.showMessage("Scanning...")
        self._save_settings()

        self.scan_worker = worker
        self.scan_worker.finished.connect(self._on_scan_complete)
        self.scan_worker.error.connect(self._on_scan_error)
        self.scan_worker.progress.connect(self._on_scan_progress)
        self.scan_worker.file_progress.connect(self._on_file_progress)
        self.scan_worker.start()

    def _reset_scan_button(self):
        self.scan_btn.setText(self._idle_scan_text())
        self._set_button_role(self.scan_btn, "primaryButton")
        self.scan_btn.setEnabled(True)
        self.progress_bar.hide()
        self.progress_label.hide()

    @staticmethod
    def _set_button_role(button, object_name: str):
        """Switch a button's QSS role; object-name selectors need an explicit re-polish."""
        button.setObjectName(object_name)
        button.style().unpolish(button)
        button.style().polish(button)

    def _on_scan_progress(self, message: str):
        metrics = self.progress_label.fontMetrics()
        self.progress_label.setText(metrics.elidedText(message, Qt.TextElideMode.ElideMiddle, 270))

    def _on_file_progress(self, current: int, total: int):
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(min(current, total))

    def _on_scan_error(self, error: str):
        self._reset_scan_button()
        self.statusbar.showMessage("Scan failed")
        QMessageBox.critical(self, "Scan Error", f"Scan failed:\n{error}")

    def _on_scan_complete(self, result: ScanResult):
        self.current_result = result
        self._reset_scan_button()
        self.stack.setCurrentIndex(1)

        score = result.metadata.get("score", {})
        self.score_display.set_score(score.get("score", 0), score.get("risk_level", "Unknown"),
                                     score.get("grade", "-"))
        total = len(result.vulnerabilities)
        for badge, sev in ((self.critical_badge, Severity.CRITICAL), (self.high_badge, Severity.HIGH),
                           (self.medium_badge, Severity.MEDIUM), (self.low_badge, Severity.LOW)):
            badge.set_count(len(result.get_vulnerabilities_by_severity(sev)), total)

        insights = build_insights(result)
        is_domain = result.metadata.get("scan_type") == "domain"
        self.tabs.setTabVisible(self.tabs.indexOf(self.deps_tab), not is_domain)
        self.tabs.setTabVisible(self.tabs.indexOf(self.secrets_tab), not is_domain)
        self.tabs.setTabVisible(self.tabs.indexOf(self.domain_tab), is_domain)
        if is_domain:
            self._update_domain_view(result)
        self._update_header(result)
        self._update_stat_cards(result, insights)
        self.vuln_list.set_vulnerabilities(result.vulnerabilities)
        self._update_overview(insights, score)
        self._update_tables(insights)
        self._update_scan_info(result)

        self.prompt_btn.setEnabled(total > 0)
        self.export_btn.setEnabled(True)
        self.copy_btn.setEnabled(True)
        self._clear_details()
        if total:
            self.vuln_list.select_row(0)

        meta = result.metadata
        hidden = []
        if meta.get("suppressed"):
            hidden.append(f"{meta['suppressed']} suppressed")
        if meta.get("baseline_hidden"):
            hidden.append(f"{meta['baseline_hidden']} in baseline")
        if meta.get("filtered_by_severity"):
            hidden.append(f"{meta['filtered_by_severity']} below severity filter")
        scope = (f"for {meta.get('target')}" if meta.get("scan_type") == "domain"
                 else f"in {result.files_scanned} files")
        status = f"Scan complete: {total} issues {scope} ({result.get_duration_seconds():.1f}s)"
        if hidden:
            status += "  -  hidden: " + ", ".join(hidden)
        if meta.get("cancelled"):
            status = "Scan cancelled - partial results.  " + status
        self.statusbar.showMessage(status)

    # ================================================================ dashboard updates

    def _update_header(self, result: ScanResult):
        if result.metadata.get("scan_type") == "domain":
            profile = result.metadata.get("domain_profile", {})
            when = result.scan_start_time.strftime("%Y-%m-%d %H:%M")
            self.project_title.setText(result.metadata.get("target", ""))
            extras = [f"Online domain scan {when}"]
            if profile.get("cdn"):
                extras.append(f"behind {profile['cdn']}")
            extras.append(f"score {result.metadata.get('score', {}).get('score', '-')}/100")
            self.project_subtitle.setText("  ·  ".join(extras))
            self.project_title.setToolTip("")
            self.project_subtitle.setToolTip("")
            return
        self.project_title.setText(Path(result.project_path).name or str(result.project_path))
        when = result.scan_start_time.strftime("%Y-%m-%d %H:%M")
        scanners = len(result.metadata.get("scanners_enabled", []))
        self.project_subtitle.setText(
            f"Scanned {when}  ·  {result.files_scanned} files  ·  {scanners} scanners  ·  "
            f"score {result.metadata.get('score', {}).get('score', '-')}/100")
        self.project_title.setToolTip(str(result.project_path))
        self.project_subtitle.setToolTip(str(result.project_path))

    def _update_stat_cards(self, result: ScanResult, insights):
        if result.metadata.get("scan_type") == "domain":
            self._update_domain_cards(result)
            return
        for card_widget, title in ((self.stat_findings, "Findings"), (self.stat_secrets, "Exposed secrets"),
                                   (self.stat_injection, "Injection risks"),
                                   (self.stat_packages, "Vulnerable packages"), (self.stat_files, "Files scanned")):
            card_widget.set_title(title)
        self._update_project_cards(result, insights)

    def _update_domain_cards(self, result: ScanResult):
        p = result.metadata.get("domain_profile", {})
        tls = p.get("tls") or {}
        total = len(result.vulnerabilities)
        crit_high = result.get_critical_count() + result.get_high_count()
        self.stat_findings.set_title("Findings")
        self.stat_findings.set_value(total, f"{crit_high} critical/high",
                                     Theme.CRITICAL if crit_high else (Theme.SUCCESS if not total else None))

        spf, dmarc = p.get("spf"), p.get("dmarc")
        dmarc_policy = re.search(r"p\s*=\s*(\w+)", dmarc or "", re.IGNORECASE)
        protected = bool(spf) and bool(dmarc_policy) and dmarc_policy.group(1).lower() in ("reject", "quarantine")
        self.stat_secrets.set_title("Email spoofing")
        self.stat_secrets.set_value("Protected" if protected else "Exposed",
                                    f"SPF {'yes' if spf else 'no'}  ·  DMARC "
                                    f"{dmarc_policy.group(1) if dmarc_policy else 'no'}",
                                    Theme.SUCCESS if protected else Theme.HIGH)

        self.stat_injection.set_title("TLS certificate")
        if tls.get("verified") and tls.get("expires_in_days") is not None:
            days = tls["expires_in_days"]
            self.stat_injection.set_value(f"{days} days", f"{tls.get('version', '')} valid",
                                          Theme.SUCCESS if days > 30 else Theme.HIGH)
        else:
            self.stat_injection.set_value("Invalid" if tls.get("reachable") else "No HTTPS",
                                          (tls.get("verify_error") or tls.get("error") or "")[:40], Theme.CRITICAL)

        dnssec = p.get("dnssec", "unknown")
        self.stat_packages.set_title("DNSSEC")
        self.stat_packages.set_value(dnssec.title(), "signed & validated" if dnssec == "validated" else "unsigned DNS",
                                     Theme.SUCCESS if dnssec == "validated" else
                                     (Theme.CRITICAL if dnssec == "broken" else Theme.MEDIUM))

        self.stat_files.set_title("CDN / WAF")
        self.stat_files.set_value(p.get("cdn") or "None", p.get("server") or "server not disclosed",
                                  Theme.SUCCESS if p.get("cdn") else Theme.TEXT_SECONDARY)
        self.tabs.setTabText(0, f"Findings  {total}")

    def _update_project_cards(self, result: ScanResult, insights):
        total = len(result.vulnerabilities)
        crit = result.get_critical_count()
        self.stat_findings.set_value(total, f"{crit} critical" if crit else "no critical issues",
                                     Theme.CRITICAL if crit else (Theme.SUCCESS if not total else None))
        self.stat_secrets.set_value(insights.secret_count, None,
                                    Theme.CRITICAL if insights.secret_count else Theme.SUCCESS)
        self.stat_injection.set_value(insights.injection_count, None,
                                      Theme.HIGH if insights.injection_count else Theme.SUCCESS)
        self.stat_packages.set_value(insights.vulnerable_packages, None,
                                     Theme.HIGH if insights.vulnerable_packages else Theme.SUCCESS)
        skipped = result.metadata.get("files_skipped", 0)
        self.stat_files.set_value(result.files_scanned,
                                  f"{skipped} skipped  ·  {result.get_duration_seconds():.1f}s")

        self.tabs.setTabText(0, f"Findings  {total}")
        self.tabs.setTabText(self.tabs.indexOf(self.deps_tab), f"Dependencies  {len(insights.dependencies)}")
        self.tabs.setTabText(self.tabs.indexOf(self.secrets_tab), f"Secrets  {insights.secret_count}")

    def _update_overview(self, insights, score: dict):
        color = Theme.get_severity_color
        self.owasp_chart.set_rows([(label, count, color(worst.name)) for label, count, worst in insights.owasp])
        self.hotspot_chart.set_rows([(label, count, color(worst.name)) for label, count, worst in insights.hotspots])
        self.category_chart.set_rows([(label, count, color(worst.name)) for label, count, worst in insights.categories])
        self.scanner_chart.set_rows([(label, count, Theme.PRIMARY) for label, count, _ in insights.scanners])

        self.fix_first_list.clear()
        for vuln in insights.fix_first:
            item = QListWidgetItem(severity_icon(vuln.severity.name), f"{vuln.title}\n{location_for(vuln)}")
            item.setData(Qt.ItemDataRole.UserRole, vuln)
            item.setToolTip(vuln.remediation)
            self.fix_first_list.addItem(item)
        if not insights.fix_first:
            self.fix_first_list.addItem("Nothing to fix - great job.")
        recs = score.get("recommendations", [])[:3]
        self.recommendations_label.setText("\n".join(f"• {r}" for r in recs))

    def _update_tables(self, insights):
        fill_table(self.deps_table, [
            (row.severity, [row.package, row.version, row.advisory, row.fixed, row.location], row.vuln)
            for row in insights.dependencies
        ])
        packages = insights.vulnerable_packages
        self.deps_hint.setText(
            f"{packages} vulnerable package(s). Double-click a row for details. "
            "Tick 'Online CVE lookup' for advisories newer than the bundled database."
            if packages else "No known-vulnerable dependencies found in the bundled database.")
        fill_table(self.secrets_table, [
            (row.severity, [row.kind, row.location, row.preview], row.vuln) for row in insights.secrets
        ])

    def _update_domain_view(self, result: ScanResult):
        e = html.escape
        p = result.metadata.get("domain_profile", {})
        tls = p.get("tls") or {}

        def status(ok: Optional[bool], text: str) -> str:
            color = Theme.SUCCESS if ok else (Theme.TEXT_TERTIARY if ok is None else Theme.HIGH)
            return f'<span style="color:{color}; font-weight:600;">{e(text)}</span>'

        def section(title: str, rows) -> str:
            body = "".join(
                f'<tr><td style="color:{Theme.TEXT_TERTIARY}; padding:4px 28px 4px 0; white-space:nowrap;">{e(k)}</td>'
                f'<td style="padding:4px 0;">{v}</td></tr>' for k, v in rows)
            return (f'<p style="font-size:14px; font-weight:700; margin-top:16px;">{e(title)}</p>'
                    f'<table cellspacing="0">{body}</table>')

        def plain(value) -> str:
            if isinstance(value, (list, tuple)):
                value = ", ".join(str(v) for v in value) if value else ""
            return e(str(value)) if value not in (None, "") else f'<span style="color:{Theme.TEXT_TERTIARY};">-</span>'

        dnssec = p.get("dnssec", "unknown")
        days = p.get("expires_in_days")
        tls_days = tls.get("expires_in_days")
        html_text = "".join([
            section("Website", [
                ("Host", plain(p.get("host"))),
                ("IPv4 / IPv6", plain((p.get("ipv4") or []) + (p.get("ipv6") or []))),
                ("CDN / WAF", status(bool(p.get("cdn")) or None, p.get("cdn") or "none detected")),
                ("Server header", plain(p.get("server"))),
                ("Final URL", plain(p.get("final_url"))),
                ("HTTP -> HTTPS", plain(p.get("http_redirect"))),
                ("security.txt", status(bool(p.get("security_txt")), "present" if p.get("security_txt") else "missing")),
            ]),
            section("TLS", [
                ("Certificate", status(bool(tls.get("verified")), "valid" if tls.get("verified")
                                       else (tls.get("verify_error") or tls.get("error") or "unavailable"))),
                ("Protocol / cipher", plain(" / ".join(x for x in (tls.get("version"), tls.get("cipher")) if x))),
                ("Issuer", plain(tls.get("issuer"))),
                ("Subject", plain(tls.get("subject"))),
                ("Valid until", plain(f"{tls.get('not_after')} ({tls_days} days)" if tls.get("not_after") else None)),
                ("Legacy TLS 1.0/1.1", status(not tls.get("legacy_protocols"),
                                              ", ".join(tls.get("legacy_protocols") or []) or "disabled")),
            ]),
            section("DNS", [
                ("Nameservers", plain(p.get("nameservers"))),
                ("DNSSEC", status(dnssec == "validated", dnssec)),
                ("CAA", status(bool(p.get("caa")), ", ".join(p.get("caa") or []) or "none (any CA may issue)")),
                ("MX", plain(p.get("mx"))),
            ]),
            section("Email authentication", [
                ("SPF", status(bool(p.get("spf")), p.get("spf") or "missing")),
                ("DMARC", status(bool(p.get("dmarc")), p.get("dmarc") or "missing")),
            ]),
            section("Registration (RDAP / WHOIS)", [
                ("Registrable domain", plain(p.get("domain"))),
                ("Registrar", plain(p.get("registrar"))),
                ("Registered", plain(p.get("registered"))),
                ("Expires", status(days is None or days > 60, f"{p.get('expires')} ({days} days)")
                 if p.get("expires") else plain(None)),
                ("Status", plain(p.get("domain_status"))),
            ]),
        ])
        if result.metadata.get("active_checks"):
            html_text += f'<p style="color:{Theme.TEXT_TERTIARY}; margin-top:16px;">Active exposed-file probing was enabled.</p>'
        self.domain_view.setHtml(f'<div style="font-size:13px;">{html_text}</div>')

    def _update_scan_info(self, result: ScanResult):
        e = html.escape
        meta = result.metadata
        rows = [
            ("Project", str(result.project_path)),
            ("Started", result.scan_start_time.strftime("%Y-%m-%d %H:%M:%S")),
            ("Duration", f"{result.get_duration_seconds():.2f}s"),
            ("Files scanned / skipped", f"{result.files_scanned} / {meta.get('files_skipped', 0)}"),
            ("Scanners enabled", ", ".join(meta.get("scanners_enabled", []))),
            ("Scanners that analysed files", ", ".join(result.scanners_used) or "-"),
            ("Duplicates merged", meta.get("duplicates_removed", 0)),
            ("Suppressed inline", meta.get("suppressed", 0)),
            ("Hidden by baseline", meta.get("baseline_hidden", 0)),
            ("Hidden by severity filter", meta.get("filtered_by_severity", 0)),
            ("Tool version", meta.get("tool_version", APP_VERSION)),
        ]
        table = "".join(
            f'<tr><td style="color:{Theme.TEXT_TERTIARY}; padding:4px 24px 4px 0;">{e(str(k))}</td>'
            f'<td style="color:{Theme.TEXT_PRIMARY}; padding:4px 0;">{e(str(v))}</td></tr>' for k, v in rows)
        warnings = "".join(f"<li>{e(w)}</li>" for w in result.errors[:200]) or "<li>None</li>"
        self.scan_info.setHtml(f"""
            <p style="font-size:15px; font-weight:700;">Scan details</p>
            <table cellspacing="0">{table}</table>
            <p style="font-size:15px; font-weight:700; margin-top:18px;">Warnings ({len(result.errors)})</p>
            <ul style="color:{Theme.TEXT_SECONDARY};">{warnings}</ul>
            <p style="color:{Theme.TEXT_TERTIARY}; margin-top:18px;">Tip: add <code>securemysite: ignore</code> in a
            comment to suppress a finding, or list paths in <code>.securemysiteignore</code>.</p>
        """)

    # ================================================================ selection & actions

    def _clear_details(self):
        self.selected_vulnerability = None
        self.details_view.show_placeholder()
        for btn in (self.quick_prompt_btn, self.open_file_btn, self.copy_location_btn, self.cwe_btn):
            btn.setEnabled(False)

    def _on_vulnerability_selected(self, vulnerability: Vulnerability):
        self.selected_vulnerability = vulnerability
        self.details_view.show_vulnerability(vulnerability)
        self.quick_prompt_btn.setEnabled(True)
        self.copy_location_btn.setEnabled(True)
        self.open_file_btn.setEnabled(bool(vulnerability.file_path))
        self.cwe_btn.setEnabled(bool(vulnerability.cwe_id))

    def _jump_to(self, vulnerability: Optional[Vulnerability]):
        if not isinstance(vulnerability, Vulnerability):
            return
        self.tabs.setCurrentIndex(0)
        if not self.vuln_list.select_vulnerability(vulnerability):
            # It may be hidden by the current filter
            self.vuln_list.search_input.clear()
            for chip in (self.vuln_list.show_critical, self.vuln_list.show_high,
                         self.vuln_list.show_medium, self.vuln_list.show_low):
                chip.setChecked(True)
            self.vuln_list.select_vulnerability(vulnerability)

    def _jump_from_table(self, table, row: int):
        item = table.item(row, 0)
        if item:
            self._jump_to(item.data(Qt.ItemDataRole.UserRole))

    def _show_text_dialog(self, title: str, text: str, default_name: str):
        # Keep a reference so the non-modal dialog is not garbage-collected
        self._text_dialog = TextDialog(self, title, text, default_name)
        self._text_dialog.show()

    def _generate_prompt(self):
        if not self.current_result:
            return
        prompt = PromptBuilder(self.current_result).build_prompt()
        QApplication.clipboard().setText(prompt)
        self.statusbar.showMessage("Prompt generated and copied to clipboard", 3000)
        self._show_text_dialog("AI Fix Prompt - All Issues", prompt, "security-fix-prompt.md")

    def _quick_fix_prompt(self):
        if not self.current_result or not self.selected_vulnerability:
            return
        prompt = PromptBuilder(self.current_result).build_quick_fix_prompt(self.selected_vulnerability)
        QApplication.clipboard().setText(prompt)
        self.statusbar.showMessage("Fix prompt copied to clipboard", 3000)
        self._show_text_dialog("AI Fix Prompt - Single Issue", prompt, "fix-prompt.md")

    def _open_selected_file(self):
        vuln = self.selected_vulnerability
        if vuln and vuln.file_path and Path(vuln.file_path).exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(vuln.file_path)))

    def _copy_location(self):
        if self.selected_vulnerability:
            QApplication.clipboard().setText(location_for(self.selected_vulnerability))
            self.statusbar.showMessage("Location copied", 2000)

    def _open_cwe(self):
        vuln = self.selected_vulnerability
        if vuln and vuln.cwe_id:
            QDesktopServices.openUrl(QUrl(f"https://cwe.mitre.org/data/definitions/{vuln.cwe_id.split('-')[-1]}.html"))

    def _copy_results(self):
        if not self.current_result:
            return
        r = self.current_result
        score = r.metadata.get("score", {})
        lines = [
            f"SecureMySite scan of {Path(r.project_path).name}",
            f"Score: {score.get('score', 'N/A')}/100 (grade {score.get('grade', '-')}, {score.get('risk_level', '')})",
            "",
        ]
        lines += [f"- {s.name.title()}: {len(r.get_vulnerabilities_by_severity(s))}" for s in Severity]
        lines += ["", "Top issues:"]
        lines += [f"- [{v.severity.name}] {v.title} ({location_for(v)})" for v in r.vulnerabilities[:10]]
        QApplication.clipboard().setText("\n".join(lines))
        self.statusbar.showMessage("Summary copied to clipboard", 3000)

    def _export_results(self, format_type: str, baseline: bool = False):
        if not self.current_result:
            QMessageBox.warning(self, "Nothing to Export", "Run a scan first.")
            return

        if baseline:
            path = str(self._baseline_path(self.current_result.project_path))
            answer = QMessageBox.question(
                self, "Save Baseline",
                f"Save the current {len(self.current_result.vulnerabilities)} findings as the baseline?\n\n"
                f"{path}\n\nScans with 'Only new since baseline' will hide them.")
            if answer != QMessageBox.StandardButton.Yes:
                return
        else:
            ext = reporter.EXTENSIONS[format_type]
            filters = {"json": "JSON (*.json)", "html": "HTML (*.html)", "markdown": "Markdown (*.md)",
                       "sarif": "SARIF (*.sarif *.json)", "csv": "CSV (*.csv)"}
            default = Path(self.current_result.project_path).name or "project"
            path, _ = QFileDialog.getSaveFileName(self, f"Export {format_type.upper()}",
                                                  f"{default}-security-report.{ext}",
                                                  filters.get(format_type, "All Files (*)"))
            if not path:
                return

        try:
            Path(path).write_text(reporter.export(self.current_result, format_type), encoding="utf-8")
            self.statusbar.showMessage(f"Saved {path}", 5000)
            if format_type == "html" and not baseline:
                QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    # ================================================================ misc

    def dragEnterEvent(self, event):
        urls = event.mimeData().urls() if event.mimeData().hasUrls() else []
        if urls and Path(urls[0].toLocalFile()).is_dir():
            event.acceptProposedAction()

    def dropEvent(self, event):
        path = event.mimeData().urls()[0].toLocalFile()
        self.path_input.setText(path)
        self._save_settings()
        self.statusbar.showMessage(f"Project set to {path}", 3000)

    def _show_about(self):
        QMessageBox.about(self, "About SecureMySite", f"""
            <h3>SecureMySite {APP_VERSION}</h3>
            <p>Local security analyzer for AI-generated web projects.</p>
            <ul>
              <li>Python, JavaScript/TypeScript, HTML &amp; template SAST</li>
              <li>Secret detection, dependency CVEs, Docker &amp; GitHub Actions checks</li>
              <li>Localhost web scanning and online domain checks (DNS, DNSSEC, SPF/DMARC, WHOIS, TLS)</li>
              <li>HTML, Markdown, JSON, SARIF and CSV reports</li>
            </ul>
            <p>Project scans stay on your machine unless you enable the OSV.dev lookup. Domain scans are online.</p>
        """)

    def closeEvent(self, event):
        self._save_settings()
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.cancel()
            if not self.scan_worker.wait(5000):
                self.scan_worker.terminate()
                self.scan_worker.wait(1000)
        event.accept()
