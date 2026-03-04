"""Primary application window for SecureMySite."""

import sys
import logging
from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QFileDialog, QMessageBox, QSplitter,
    QTextEdit, QGroupBox, QGridLayout, QStatusBar, QMenuBar,
    QMenu, QApplication, QFrame, QGraphicsDropShadowEffect
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings
from PyQt6.QtGui import QAction, QKeySequence, QColor

from core.engine import AnalysisEngine
from core.config import Config
from models.scan_result import ScanResult
from models.vulnerability import Vulnerability, Severity
from prompt_engine.prompt_builder import PromptBuilder
from gui.theme import Theme
from gui.components import (
    ScoreDisplay, VulnerabilityList, CodePreview,
    ProgressWidget, SeverityBadge
)
from utils.validators import validate_project_path, validate_url


class ScanWorker(QThread):
    """Background worker for security scanning."""
    
    finished = pyqtSignal(object)  # ScanResult
    error = pyqtSignal(str)
    progress = pyqtSignal(str)
    
    def __init__(self, project_path: Path, url: Optional[str] = None):
        super().__init__()
        self.project_path = project_path
        self.url = url
        self.engine: Optional[AnalysisEngine] = None
    
    def run(self):
        """Execute scan."""
        try:
            self.progress.emit("Initializing scanner...")
            self.engine = AnalysisEngine(self.project_path)
            
            self.progress.emit("Scanning files...")
            result = self.engine.analyze(self.url)
            
            self.progress.emit("Complete")
            self.finished.emit(result)
            
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            self.error.emit(str(e))


class MainWindow(QMainWindow):
    """Primary application window."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(Config.GUI_WINDOW_TITLE)
        self.setMinimumSize(Config.GUI_MIN_WIDTH, Config.GUI_MIN_HEIGHT)
        self.resize(Config.GUI_DEFAULT_WIDTH, Config.GUI_DEFAULT_HEIGHT)
        
        # State
        self.current_result: Optional[ScanResult] = None
        self.scan_worker: Optional[ScanWorker] = None
        self.settings = QSettings("SecureMySite", "App")
        
        # Setup
        self._setup_menu()
        self._setup_ui()
        self._apply_theme()
        self._load_settings()
    
    def _setup_menu(self):
        """Setup menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        open_action = QAction("Open Project...", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self._browse_project)
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        export_json = QAction("Export JSON...", self)
        export_json.triggered.connect(lambda: self._export_results("json"))
        file_menu.addAction(export_json)
        
        export_html = QAction("Export HTML...", self)
        export_html.triggered.connect(lambda: self._export_results("html"))
        file_menu.addAction(export_html)
        
        export_md = QAction("Export Markdown...", self)
        export_md.triggered.connect(lambda: self._export_results("markdown"))
        file_menu.addAction(export_md)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
    
    def _setup_ui(self):
        """Setup modern main UI."""
        central = QWidget()
        self.setCentralWidget(central)
        
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(32, 24, 32, 24)
        
        # Modern header with logo area
        header_container = self._create_header()
        main_layout.addWidget(header_container)
        
        # Input section (modern card)
        input_group = self._create_input_section()
        main_layout.addWidget(input_group)
        
        # Score dashboard (modern layout)
        score_container = self._create_score_dashboard()
        main_layout.addWidget(score_container)
        
        # Results area with modern splitter
        results_container = self._create_results_area()
        main_layout.addWidget(results_container, 1)
        
        # Progress widget
        self.progress = ProgressWidget()
        main_layout.addWidget(self.progress)
        
        # Modern status bar
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Ready")
    
    def _create_header(self) -> QFrame:
        """Create modern header with title and subtitle."""
        header = QFrame()
        header.setStyleSheet(f"""
            QFrame {{
                background-color: transparent;
                border: none;
            }}
        """)
        
        layout = QVBoxLayout(header)
        layout.setSpacing(4)
        layout.setContentsMargins(0, 0, 0, 8)
        
        # Main title with gradient effect
        title = QLabel("Secure My Site")
        title.setObjectName("titleLabel")
        title.setStyleSheet(f"""
            QLabel {{
                font-size: 32px;
                font-weight: 700;
                color: {Theme.TEXT_PRIMARY};
                background: transparent;
            }}
        """)
        
        # Subtitle
        subtitle = QLabel("Local Security Analyzer for AI-Generated Projects")
        subtitle.setStyleSheet(f"""
            QLabel {{
                font-size: 14px;
                color: {Theme.TEXT_SECONDARY};
                background: transparent;
            }}
        """)
        
        layout.addWidget(title)
        layout.addWidget(subtitle)
        
        return header
    
    def _create_input_section(self) -> QGroupBox:
        """Create modern project input section."""
        group = QGroupBox("Project Configuration")
        group.setStyleSheet(f"""
            QGroupBox {{
                background-color: {Theme.SURFACE};
                border: 1px solid {Theme.BORDER};
                border-radius: {Theme.BORDER_RADIUS_LARGE};
                margin-top: 16px;
                padding-top: 16px;
                padding: 20px;
                font-weight: 600;
                font-size: 16px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 16px;
                padding: 0 8px;
                color: {Theme.TEXT_PRIMARY};
            }}
        """)
        
        layout = QGridLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(8, 8, 8, 8)
        
        # Project path with modern styling
        path_label = QLabel("Project Path")
        path_label.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 13px; font-weight: 500;")
        layout.addWidget(path_label, 0, 0)
        
        path_layout = QHBoxLayout()
        path_layout.setSpacing(8)
        
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("/path/to/your/project")
        self.path_input.setMinimumHeight(36)
        
        browse_btn = QPushButton("Browse")
        browse_btn.setObjectName("secondaryButton")
        browse_btn.setMinimumHeight(36)
        browse_btn.clicked.connect(self._browse_project)
        
        path_layout.addWidget(self.path_input)
        path_layout.addWidget(browse_btn)
        
        layout.addLayout(path_layout, 0, 1)
        
        # URL input with modern styling
        url_label = QLabel("Local URL")
        url_label.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 13px; font-weight: 500;")
        layout.addWidget(url_label, 1, 0)
        
        url_layout = QHBoxLayout()
        url_layout.setSpacing(8)
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://localhost:8000 (optional)")
        self.url_input.setMinimumHeight(36)
        
        validate_btn = QPushButton("Validate")
        validate_btn.setObjectName("secondaryButton")
        validate_btn.setMinimumHeight(36)
        validate_btn.clicked.connect(self._validate_url)
        
        url_layout.addWidget(self.url_input)
        url_layout.addWidget(validate_btn)
        
        layout.addLayout(url_layout, 1, 1)
        
        # Modern scan button
        self.scan_btn = QPushButton("Start Security Analysis")
        self.scan_btn.setObjectName("primaryButton")
        self.scan_btn.setMinimumHeight(44)
        self.scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_btn.clicked.connect(self._start_scan)
        
        layout.addWidget(self.scan_btn, 2, 0, 1, 2)
        
        group.setLayout(layout)
        return group
    
    def _create_score_dashboard(self) -> QFrame:
        """Create modern score dashboard."""
        container = QFrame()
        container.setStyleSheet(f"""
            QFrame {{
                background-color: {Theme.SURFACE};
                border: 1px solid {Theme.BORDER};
                border-radius: {Theme.BORDER_RADIUS_LARGE};
            }}
        """)
        
        # Add shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 60))
        shadow.setOffset(0, 4)
        container.setGraphicsEffect(shadow)
        
        layout = QHBoxLayout(container)
        layout.setSpacing(24)
        layout.setContentsMargins(24, 20, 24, 20)
        
        # Animated score display
        self.score_display = ScoreDisplay()
        layout.addWidget(self.score_display, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # Vertical separator
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.VLine)
        separator.setStyleSheet(f"color: {Theme.BORDER};")
        separator.setFixedWidth(1)
        layout.addWidget(separator)
        
        # Severity counts in modern layout
        counts_container = QFrame()
        counts_layout = QVBoxLayout(counts_container)
        counts_layout.setSpacing(8)
        counts_layout.setContentsMargins(0, 0, 0, 0)
        
        self.critical_badge = SeverityBadge(Severity.CRITICAL, 0)
        self.high_badge = SeverityBadge(Severity.HIGH, 0)
        self.medium_badge = SeverityBadge(Severity.MEDIUM, 0)
        self.low_badge = SeverityBadge(Severity.LOW, 0)
        
        counts_layout.addWidget(self.critical_badge)
        counts_layout.addWidget(self.high_badge)
        counts_layout.addWidget(self.medium_badge)
        counts_layout.addWidget(self.low_badge)
        
        layout.addLayout(counts_layout)
        
        # Another separator
        separator2 = QFrame()
        separator2.setFrameShape(QFrame.Shape.VLine)
        separator2.setStyleSheet(f"color: {Theme.BORDER};")
        separator2.setFixedWidth(1)
        layout.addWidget(separator2)
        
        # Action buttons with modern styling
        actions_container = QFrame()
        actions_layout = QVBoxLayout(actions_container)
        actions_layout.setSpacing(10)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        
        self.prompt_btn = QPushButton("Generate AI Fix Prompt")
        self.prompt_btn.setObjectName("secondaryButton")
        self.prompt_btn.setMinimumHeight(36)
        self.prompt_btn.clicked.connect(self._generate_prompt)
        self.prompt_btn.setEnabled(False)
        
        self.copy_btn = QPushButton("Copy Results")
        self.copy_btn.setObjectName("secondaryButton")
        self.copy_btn.setMinimumHeight(36)
        self.copy_btn.clicked.connect(self._copy_results)
        self.copy_btn.setEnabled(False)
        
        actions_layout.addWidget(self.prompt_btn)
        actions_layout.addWidget(self.copy_btn)
        actions_layout.addStretch()
        
        layout.addLayout(actions_layout)
        layout.addStretch()
        
        return container
    
    def _create_results_area(self) -> QSplitter:
        """Create modern results area with splitter."""
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(2)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {Theme.BORDER};
            }}
        """)
        
        # Vulnerability list (modern)
        self.vuln_list = VulnerabilityList()
        self.vuln_list.vulnerability_selected.connect(self._on_vulnerability_selected)
        self.vuln_list.setMinimumWidth(350)
        splitter.addWidget(self.vuln_list)
        
        # Details panel (modern)
        self.details_panel = self._create_details_panel()
        self.details_panel.setMinimumWidth(400)
        splitter.addWidget(self.details_panel)
        
        splitter.setSizes([450, 550])
        
        return splitter
    
    def _create_details_panel(self) -> QGroupBox:
        """Create modern vulnerability details panel."""
        group = QGroupBox("Vulnerability Details")
        group.setStyleSheet(f"""
            QGroupBox {{
                background-color: {Theme.SURFACE};
                border: 1px solid {Theme.BORDER};
                border-radius: {Theme.BORDER_RADIUS_LARGE};
                margin-top: 0px;
                padding: 20px;
                font-weight: 600;
                font-size: 16px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 0px;
                padding: 0 0px;
                color: {Theme.TEXT_PRIMARY};
            }}
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(16)
        layout.setContentsMargins(4, 4, 4, 4)
        
        # Title with severity badge style
        self.details_title = QLabel("Select a vulnerability to view details")
        self.details_title.setWordWrap(True)
        self.details_title.setStyleSheet(f"""
            QLabel {{
                font-weight: 600;
                font-size: 16px;
                color: {Theme.TEXT_PRIMARY};
                padding-bottom: 8px;
                border-bottom: 1px solid {Theme.BORDER};
            }}
        """)
        layout.addWidget(self.details_title)
        
        # Location with icon
        self.details_location = QLabel("")
        self.details_location.setStyleSheet(f"""
            QLabel {{
                color: {Theme.TEXT_TERTIARY};
                font-size: 12px;
                font-family: {Theme.FONT_MONO};
            }}
        """)
        layout.addWidget(self.details_location)
        
        # Description section
        desc_header = QLabel("Description")
        desc_header.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px; font-weight: 600; text-transform: uppercase;")
        layout.addWidget(desc_header)
        
        self.details_desc = QLabel("")
        self.details_desc.setWordWrap(True)
        self.details_desc.setStyleSheet(f"""
            QLabel {{
                color: {Theme.TEXT_SECONDARY};
                font-size: 13px;
                line-height: 1.5;
            }}
        """)
        layout.addWidget(self.details_desc)
        
        # Remediation section
        fix_header = QLabel("Recommended Fix")
        fix_header.setStyleSheet(f"color: {Theme.PRIMARY}; font-size: 12px; font-weight: 600; text-transform: uppercase;")
        layout.addWidget(fix_header)
        
        self.details_remediation = QLabel("")
        self.details_remediation.setWordWrap(True)
        self.details_remediation.setStyleSheet(f"""
            QLabel {{
                color: {Theme.PRIMARY};
                font-size: 13px;
                line-height: 1.5;
            }}
        """)
        layout.addWidget(self.details_remediation)
        
        # Code preview section
        code_header = QLabel("Code Snippet")
        code_header.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 12px; font-weight: 600; text-transform: uppercase;")
        layout.addWidget(code_header)
        
        self.code_preview = CodePreview()
        self.code_preview.setMaximumHeight(250)
        layout.addWidget(self.code_preview)
        
        layout.addStretch()
        group.setLayout(layout)
        return group
    
    def _apply_theme(self):
        """Apply dark theme stylesheet."""
        self.setStyleSheet(Theme.get_stylesheet())
    
    def _load_settings(self):
        """Load saved settings."""
        last_path = self.settings.value("last_project_path", "")
        if last_path:
            self.path_input.setText(last_path)
    
    def _save_settings(self):
        """Save current settings."""
        self.settings.setValue("last_project_path", self.path_input.text())
    
    def _browse_project(self):
        """Open directory browser."""
        path = QFileDialog.getExistingDirectory(
            self,
            "Select Project Directory",
            self.path_input.text() or str(Path.home())
        )
        
        if path:
            self.path_input.setText(path)
            self._save_settings()
    
    def _validate_url(self):
        """Validate URL input."""
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.information(self, "Validation", "URL is optional")
            return
        
        is_valid, error = validate_url(url)
        if is_valid:
            QMessageBox.information(self, "Validation", "URL is valid (localhost only)")
        else:
            QMessageBox.warning(self, "Invalid URL", error)
    
    def _start_scan(self):
        """Start security scan."""
        path_text = self.path_input.text().strip()
        
        if not path_text:
            QMessageBox.warning(self, "Error", "Please select a project directory")
            return
        
        is_valid, error = validate_project_path(path_text)
        if not is_valid:
            QMessageBox.warning(self, "Invalid Path", error)
            return
        
        # Get optional URL
        url = self.url_input.text().strip() or None
        if url:
            is_valid, error = validate_url(url)
            if not is_valid:
                QMessageBox.warning(self, "Invalid URL", error)
                return
        
        # Start scan
        self._run_scan(Path(path_text), url)
    
    def _run_scan(self, project_path: Path, url: Optional[str]):
        """Run scan in background thread."""
        self.scan_btn.setEnabled(False)
        self.progress.show_progress()
        self.statusbar.showMessage("Scanning...")
        
        self.scan_worker = ScanWorker(project_path, url)
        self.scan_worker.finished.connect(self._on_scan_complete)
        self.scan_worker.error.connect(self._on_scan_error)
        self.scan_worker.progress.connect(self._on_scan_progress)
        self.scan_worker.start()
    
    def _on_scan_progress(self, message: str):
        """Update scan progress."""
        self.progress.set_status(message)
        self.statusbar.showMessage(message)
    
    def _on_scan_complete(self, result: ScanResult):
        """Handle scan completion."""
        self.current_result = result
        self.scan_btn.setEnabled(True)
        self.progress.hide_progress()
        
        # Update score display
        if result.metadata and 'score' in result.metadata:
            score_data = result.metadata['score']
            self.score_display.set_score(
                score_data.get('score', 0),
                score_data.get('risk_level', 'Unknown'),
                score_data.get('grade', '-')
            )
        
        # Update severity counts
        self.critical_badge.set_count(result.get_critical_count())
        self.high_badge.set_count(result.get_high_count())
        self.medium_badge.set_count(result.get_medium_count())
        self.low_badge.set_count(result.get_low_count())
        
        # Update vulnerability list
        self.vuln_list.set_vulnerabilities(result.vulnerabilities)
        
        # Enable action buttons
        has_results = len(result.vulnerabilities) > 0
        self.prompt_btn.setEnabled(has_results)
        self.copy_btn.setEnabled(has_results)
        
        # Update status
        summary = result.get_summary()
        self.statusbar.showMessage(
            f"Scan complete: {summary['total_vulnerabilities']} issues found in {summary['files_scanned']} files"
        )
    
    def _on_scan_error(self, error: str):
        """Handle scan error."""
        self.scan_btn.setEnabled(True)
        self.progress.hide_progress()
        self.statusbar.showMessage("Scan failed")
        
        QMessageBox.critical(self, "Scan Error", f"Scan failed:\n{error}")
    
    def _on_vulnerability_selected(self, vulnerability: Vulnerability):
        """Display vulnerability details."""
        self.details_title.setText(f"[{vulnerability.severity.name}] {vulnerability.title}")
        self.details_location.setText(vulnerability.get_location_string())
        self.details_desc.setText(vulnerability.description)
        self.details_remediation.setText(f"Fix: {vulnerability.remediation}")
        
        if vulnerability.code_snippet:
            self.code_preview.set_code(vulnerability.code_snippet)
        else:
            self.code_preview.clear_code()
    
    def _generate_prompt(self):
        """Generate AI fix prompt."""
        if not self.current_result:
            return
        
        builder = PromptBuilder(self.current_result)
        prompt = builder.build_prompt()
        
        # Show in dialog
        dialog = QTextEdit()
        dialog.setPlainText(prompt)
        dialog.setReadOnly(True)
        dialog.setWindowTitle("AI Fix Prompt")
        dialog.resize(800, 600)
        dialog.show()
        
        # Also copy to clipboard
        clipboard = QApplication.clipboard()
        clipboard.setText(prompt)
        
        self.statusbar.showMessage("Prompt generated and copied to clipboard", 3000)
    
    def _copy_results(self):
        """Copy results summary to clipboard."""
        if not self.current_result:
            return
        
        summary = self.current_result.get_summary()
        score_data = self.current_result.metadata.get('score', {})
        text = f"""Security Scan Results

Score: {score_data.get('score', 'N/A')}/100
Risk Level: {score_data.get('risk_level', 'Unknown')}

Vulnerabilities:
- Critical: {summary['critical']}
- High: {summary['high']}
- Medium: {summary['medium']}
- Low: {summary['low']}

Files Scanned: {summary['files_scanned']}
Duration: {summary['duration_seconds']:.1f}s
"""
        
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        
        self.statusbar.showMessage("Results copied to clipboard", 3000)
    
    def _export_results(self, format_type: str):
        """Export results to file."""
        if not self.current_result:
            QMessageBox.warning(self, "Error", "No scan results to export")
            return
        
        # Get save path
        extensions = {
            "json": "JSON (*.json)",
            "html": "HTML (*.html)",
            "markdown": "Markdown (*.md)"
        }
        
        path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export {format_type.upper()}",
            f"security_report.{format_type if format_type != 'markdown' else 'md'}",
            extensions.get(format_type, "All Files (*)")
        )
        
        if not path:
            return
        
        try:
            if self.scan_worker and self.scan_worker.engine:
                content = self.scan_worker.engine.export_results(format_type)
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                self.statusbar.showMessage(f"Exported to {path}", 3000)
            else:
                QMessageBox.warning(self, "Error", "Scan engine not available")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))
    
    def _show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About Secure My Site",
            """<h2>Secure My Site</h2>
            <p>Version 1.0.0</p>
            <p>A local security analyzer for AI-generated web projects.</p>
            <p>Features:</p>
            <ul>
                <li>Static Application Security Testing (SAST)</li>
                <li>Dependency vulnerability scanning</li>
                <li>Configuration security analysis</li>
                <li>Localhost web security scanning</li>
                <li>AI-powered fix generation</li>
            </ul>
            <p>100% offline - no data leaves your machine.</p>
            """
        )
    
    def closeEvent(self, event):
        """Handle window close."""
        self._save_settings()
        
        # Stop any running scan
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.terminate()
            self.scan_worker.wait(1000)
        
        event.accept()
