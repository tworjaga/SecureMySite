"""Reusable UI components for SecureMySite GUI."""

from typing import Optional, List, Callable
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QTextEdit, QFrame,
    QSizePolicy, QProgressBar, QGridLayout
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QColor, QPalette

from models.vulnerability import Vulnerability, Severity
from gui.theme import Theme


class ScoreDisplay(QWidget):
    """Circular score display widget."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.score = 0
        self.risk_level = "Unknown"
        self.grade = "-"
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(8)
        
        # Score label
        self.score_label = QLabel("--")
        self.score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(48)
        font.setBold(True)
        self.score_label.setFont(font)
        self.score_label.setStyleSheet(f"color: {Theme.TEXT_SECONDARY};")
        
        # Risk level label
        self.risk_label = QLabel("No Scan")
        self.risk_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(14)
        self.risk_label.setFont(font)
        self.risk_label.setStyleSheet(f"color: {Theme.TEXT_SECONDARY};")
        
        # Grade label
        self.grade_label = QLabel("-")
        self.grade_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(24)
        font.setBold(True)
        self.grade_label.setFont(font)
        self.grade_label.setStyleSheet(f"color: {Theme.TEXT_SECONDARY};")
        
        layout.addWidget(self.score_label)
        layout.addWidget(self.risk_label)
        layout.addWidget(self.grade_label)
        
        self.setMinimumSize(200, 200)
    
    def set_score(self, score: int, risk_level: str, grade: str):
        """Update score display."""
        self.score = score
        self.risk_level = risk_level
        self.grade = grade
        
        self.score_label.setText(str(score))
        self.risk_label.setText(risk_level)
        self.grade_label.setText(grade)
        
        # Update colors based on score
        color = Theme.get_score_color(score)
        self.score_label.setStyleSheet(f"color: {color};")
        self.grade_label.setStyleSheet(f"color: {color};")
    
    def reset(self):
        """Reset to default state."""
        self.score = 0
        self.risk_level = "Unknown"
        self.grade = "-"
        self.score_label.setText("--")
        self.risk_label.setText("No Scan")
        self.grade_label.setText("-")
        self.score_label.setStyleSheet(f"color: {Theme.TEXT_SECONDARY};")
        self.grade_label.setStyleSheet(f"color: {Theme.TEXT_SECONDARY};")


class SeverityBadge(QWidget):
    """Severity badge widget."""
    
    def __init__(self, severity: Severity, count: int = 0, parent=None):
        super().__init__(parent)
        self.severity = severity
        self.count = count
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(8)
        
        # Color indicator
        self.indicator = QFrame()
        self.indicator.setFixedSize(12, 12)
        self.indicator.setFrameShape(QFrame.Shape.StyledPanel)
        self.indicator.setStyleSheet(f"""
            QFrame {{
                background-color: {Theme.get_severity_color(self.severity.name)};
                border-radius: 6px;
            }}
        """)
        
        # Label
        self.label = QLabel(f"{self.severity.name}: {self.count}")
        self.label.setStyleSheet(f"color: {Theme.TEXT_PRIMARY}; font-weight: bold;")
        
        layout.addWidget(self.indicator)
        layout.addWidget(self.label)
        layout.addStretch()
        
        self.setStyleSheet(f"""
            SeverityBadge {{
                background-color: {Theme.SURFACE};
                border-radius: {Theme.BORDER_RADIUS_NORMAL};
                border: 1px solid {Theme.BORDER};
            }}
        """)
    
    def set_count(self, count: int):
        """Update count display."""
        self.count = count
        self.label.setText(f"{self.severity.name}: {count}")


class VulnerabilityItem(QWidget):
    """Single vulnerability list item."""
    
    clicked = pyqtSignal(object)  # Emits Vulnerability
    
    def __init__(self, vulnerability: Vulnerability, parent=None):
        super().__init__(parent)
        self.vulnerability = vulnerability
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)
        
        # Header row
        header = QHBoxLayout()
        
        # Severity badge
        self.severity_label = QLabel(self.vulnerability.severity.name)
        self.severity_label.setStyleSheet(f"""
            QLabel {{
                color: {Theme.get_severity_color(self.vulnerability.severity.name)};
                font-weight: bold;
                font-size: 12px;
                padding: 2px 8px;
                background-color: {Theme.SURFACE_DARK};
                border-radius: 4px;
            }}
        """)
        
        # Title
        self.title_label = QLabel(self.vulnerability.title)
        self.title_label.setStyleSheet(f"color: {Theme.TEXT_PRIMARY}; font-weight: bold;")
        self.title_label.setWordWrap(True)
        
        header.addWidget(self.severity_label)
        header.addWidget(self.title_label, 1)
        
        # Location
        self.location_label = QLabel(self.vulnerability.get_location_string())
        self.location_label.setStyleSheet(f"color: {Theme.TEXT_SECONDARY}; font-size: 11px;")
        
        # Description (truncated)
        self.desc_label = QLabel(self.vulnerability.description)
        self.desc_label.setStyleSheet(f"color: {Theme.TEXT_SECONDARY};")
        self.desc_label.setWordWrap(True)
        self.desc_label.setMaximumHeight(40)
        
        layout.addLayout(header)
        layout.addWidget(self.location_label)
        layout.addWidget(self.desc_label)
        
        # Styling
        self.setStyleSheet(f"""
            VulnerabilityItem {{
                background-color: {Theme.SURFACE};
                border-left: 4px solid {Theme.get_severity_color(self.vulnerability.severity.name)};
                border-radius: {Theme.BORDER_RADIUS_NORMAL};
            }}
            VulnerabilityItem:hover {{
                background-color: {Theme.SURFACE_LIGHT};
            }}
        """)
        
        self.setCursor(Qt.CursorShape.PointingHandCursor)
    
    def mousePressEvent(self, event):
        """Handle click."""
        self.clicked.emit(self.vulnerability)
        super().mousePressEvent(event)


class VulnerabilityList(QWidget):
    """List of vulnerabilities with filtering."""
    
    vulnerability_selected = pyqtSignal(object)  # Emits Vulnerability
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.vulnerabilities: List[Vulnerability] = []
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Filter buttons
        filter_layout = QHBoxLayout()
        
        self.show_critical = QPushButton("Critical")
        self.show_critical.setCheckable(True)
        self.show_critical.setChecked(True)
        self.show_critical.clicked.connect(self._apply_filter)
        
        self.show_high = QPushButton("High")
        self.show_high.setCheckable(True)
        self.show_high.setChecked(True)
        self.show_high.clicked.connect(self._apply_filter)
        
        self.show_medium = QPushButton("Medium")
        self.show_medium.setCheckable(True)
        self.show_medium.setChecked(True)
        self.show_medium.clicked.connect(self._apply_filter)
        
        self.show_low = QPushButton("Low")
        self.show_low.setCheckable(True)
        self.show_low.setChecked(True)
        self.show_low.clicked.connect(self._apply_filter)
        
        filter_layout.addWidget(self.show_critical)
        filter_layout.addWidget(self.show_high)
        filter_layout.addWidget(self.show_medium)
        filter_layout.addWidget(self.show_low)
        filter_layout.addStretch()
        
        # List widget
        self.list_widget = QListWidget()
        self.list_widget.setSpacing(8)
        self.list_widget.setStyleSheet(f"""
            QListWidget {{
                background-color: {Theme.BACKGROUND};
                border: none;
            }}
            QListWidget::item {{
                background: transparent;
                padding: 0px;
            }}
        """)
        
        layout.addLayout(filter_layout)
        layout.addWidget(self.list_widget)
    
    def set_vulnerabilities(self, vulnerabilities: List[Vulnerability]):
        """Set list of vulnerabilities."""
        self.vulnerabilities = vulnerabilities
        self._apply_filter()
    
    def _apply_filter(self):
        """Apply filters and populate list."""
        self.list_widget.clear()
        
        # Get filter states
        show_severities = set()
        if self.show_critical.isChecked():
            show_severities.add(Severity.CRITICAL)
        if self.show_high.isChecked():
            show_severities.add(Severity.HIGH)
        if self.show_medium.isChecked():
            show_severities.add(Severity.MEDIUM)
        if self.show_low.isChecked():
            show_severities.add(Severity.LOW)
        
        # Filter and sort (critical first)
        filtered = [v for v in self.vulnerabilities if v.severity in show_severities]
        filtered.sort(key=lambda v: v.severity.value)
        
        # Add items
        for vuln in filtered:
            item = QListWidgetItem()
            item.setSizeHint(QSize(0, 100))
            
            widget = VulnerabilityItem(vuln)
            widget.clicked.connect(self._on_vulnerability_clicked)
            
            self.list_widget.addItem(item)
            self.list_widget.setItemWidget(item, widget)
    
    def _on_vulnerability_clicked(self, vulnerability: Vulnerability):
        """Handle vulnerability click."""
        self.vulnerability_selected.emit(vulnerability)
    
    def clear(self):
        """Clear all vulnerabilities."""
        self.vulnerabilities = []
        self.list_widget.clear()


class CodePreview(QTextEdit):
    """Code preview with syntax highlighting."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.setStyleSheet(f"""
            QTextEdit {{
                background-color: {Theme.SURFACE_DARK};
                color: {Theme.TEXT_PRIMARY};
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
                border: 1px solid {Theme.BORDER};
                border-radius: {Theme.BORDER_RADIUS_NORMAL};
                padding: 12px;
            }}
        """)
    
    def set_code(self, code: str, language: str = "python"):
        """Set code content."""
        self.setPlainText(code)
    
    def clear_code(self):
        """Clear code content."""
        self.clear()


class ProgressWidget(QWidget):
    """Progress indicator with status text."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self.hide()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedWidth(300)
        
        self.status_label = QLabel("Scanning...")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet(f"color: {Theme.TEXT_SECONDARY};")
        
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.status_label)
        
        self.setStyleSheet(f"""
            ProgressWidget {{
                background-color: {Theme.BACKGROUND};
            }}
        """)
    
    def set_status(self, text: str):
        """Update status text."""
        self.status_label.setText(text)
    
    def show_progress(self):
        """Show progress widget."""
        self.show()
        self.progress_bar.setRange(0, 0)
    
    def hide_progress(self):
        """Hide progress widget."""
        self.hide()


class ActionButton(QPushButton):
    """Styled action button."""
    
    def __init__(self, text: str, primary: bool = False, parent=None):
        super().__init__(text, parent)
        self.primary = primary
        self._apply_style()
    
    def _apply_style(self):
        if self.primary:
            self.setObjectName("primaryButton")
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {Theme.SURFACE};
                    color: {Theme.TEXT_PRIMARY};
                    border: 1px solid {Theme.BORDER};
                    border-radius: {Theme.BORDER_RADIUS_NORMAL};
                    padding: 8px 16px;
                }}
                QPushButton:hover {{
                    background-color: {Theme.SURFACE_LIGHT};
                    border-color: {Theme.BORDER_LIGHT};
                }}
            """)
