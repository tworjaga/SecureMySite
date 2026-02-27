"""Primary application window for SecureMySite."""

import sys
import logging
from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QFileDialog, QMessageBox, QSplitter,
    QTextEdit, QGroupBox, QGridLayout, QStatusBar, QMenuBar,
    QMenu, QApplication
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings
from PyQt6.QtGui import QAction, QKeySequence

from core.engine import AnalysisEngine
from core.config import Config
from models.scan_result import ScanResult
from models.vulnerability import Vulnerability, Severity
from prompt_engine.prompt_builder import PromptBuilder
from gui.theme import Theme
from gui.components import (
    ScoreDisplay, VulnerabilityList, CodePreview,
    ProgressWidget, ActionButton, SeverityBadge
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
        """Setup main UI."""
        central = QWidget()
        self.setCentralWidget(central)
        
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(16)
        main_layout.setContentsMargins(24, 24, 24, 24)
        
        # Header
        header = QLabel("Secure My Site")
        header.setObjectName("titleLabel")
        header.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {Theme.PRIMARY};")
        main_layout.addWidget(header)
        
        # Input section
        input_group = self._create_input_section()
        main_layout.addWidget(input_group)
        
        # Score section
        score_group = self._create_score_section()
        main_layout.addWidget(score_group)
        
        # Results splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Vulnerability list
        self.vuln_list = VulnerabilityList()
        self.vuln_list.vulnerability_selected.connect(self._on_vulnerability_selected)
        splitter.addWidget(self.vuln_list)
        
        # Details panel
        self.details_panel = self._create_details_panel()
        splitter.addWidget(self.details_panel)
        
        splitter.setSizes([400, 500])
        main_layout.addWidget(splitter, 1)
        
        # Progress widget
        self.progress = ProgressWidget()
        main_layout.addWidget(self.progress)
        
        # Status bar
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Ready")
    
    def _create_input_section(self) -> QGroupBox:
        """Create project input section."""
        group = QGroupBox("Project Configuration")
        
        layout = QGridLayout()
        layout.setSpacing(12)
        
        # Project path
        layout.addWidget(QLabel("Project Path:"), 0, 0)
        
        path_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Select project directory...")
        path_layout.addWidget(self.path_input)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_project)
        path_layout.addWidget(browse_btn)
        
        layout.addLayout(path_layout, 0, 1)
        
        # URL input
        layout.addWidget(QLabel("Local URL:"), 1, 0)
        
        url_layout = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://localhost:8000 (optional)")
        url_layout.addWidget(self.url_input)
        
        validate_btn = QPushButton("Validate")
        validate_btn.clicked.connect(self._validate_url)
        url_layout.addWidget(validate_btn)
        
        layout.addLayout(url_layout, 1, 1)
        
        # Scan button
        self.scan_btn = ActionButton("Start Security Analysis", primary=True)
        self.scan_btn.clicked.connect(self._start_scan)
        self.scan_btn.setMinimumHeight(40)
        layout.addWidget(self.scan_btn, 2, 0, 1, 2)
        
        group.setLayout(layout)
        return group
    
    def _create_score_section(self) -> QGroupBox:
        """Create score display section."""
        group = QGroupBox("Security Score")
        
        layout = QHBoxLayout()
        layout.setSpacing(24)
        
        # Score display
        self.score_display = ScoreDisplay()
        layout.addWidget(self.score_display)
        
        # Severity counts
        counts_layout = QVBoxLayout()
        
        self.critical_badge = SeverityBadge(Severity.CRITICAL, 0)
        self.high_badge = SeverityBadge(Severity.HIGH, 0)
        self.medium_badge = SeverityBadge(Severity.MEDIUM, 0)
        self.low_badge = SeverityBadge(Severity.LOW, 0)
        
        counts_layout.addWidget(self.critical_badge)
        counts_layout.addWidget(self.high_badge)
        counts_layout.addWidget(self.medium_badge)
        counts_layout.addWidget(self.low_badge)
        counts_layout.addStretch()
        
        layout.addLayout(counts_layout)
        layout.addStretch()
        
        # Action buttons
        actions_layout = QVBoxLayout()
        
        self.prompt_btn = QPushButton("Generate Fix Prompt")
        self.prompt_btn.clicked.connect(self._generate_prompt)
        self.prompt_btn.setEnabled(False)
        actions_layout.addWidget(self.prompt_btn)
        
        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.clicked.connect(self._copy_results)
        self.copy_btn.setEnabled(False)
        actions_layout.addWidget(self.copy_btn)
        
        actions_layout.addStretch()
        layout.addLayout(actions_layout)
        
        group.setLayout(layout)
        return group
    
    def _create_details_panel(self) -> QGroupBox:
        """Create vulnerability details panel."""
        group = QGroupBox("Vulnerability Details")
        
        layout = QVBoxLayout()
        
        self.details_title = QLabel("Select a vulnerability to view details")
        self.details_title.setWordWrap(True)
        self.details_title.setStyleSheet(f"font-weight: bold; color: {Theme.TEXT_PRIMARY};")
        layout.addWidget(self.details_title)
        
        self.details_location = QLabel("")
        self.details_location.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 11px;")
        layout.addWidget(self.details_location)
        
        self.details_desc = QLabel("")
        self.details_desc.setWordWrap(True)
        self.details_desc.setStyleSheet(f"color: {Theme.TEXT_SECONDARY};")
        layout.addWidget(self.details_desc)
        
        self.details_remediation = QLabel("")
        self.details_remediation.setWordWrap(True)
        self.details_remediation.setStyleSheet(f"color: {Theme.PRIMARY};")
        layout.addWidget(self.details_remediation)
        
        # Code preview
        layout.addWidget(QLabel("Code:"))
        self.code_preview = CodePreview()
        self.code_preview.setMaximumHeight(200)
        layout.addWidget(self.code_preview)
        
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
