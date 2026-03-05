"""Modern reusable UI components for SecureMySite GUI."""

from typing import Optional, List, Callable
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QTextEdit, QFrame,
    QSizePolicy, QProgressBar, QGridLayout, QGraphicsDropShadowEffect
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize, QTimer, QPropertyAnimation, QEasingCurve, QRectF, pyqtProperty
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush, QConicalGradient

from models.vulnerability import Vulnerability, Severity

from gui.theme import Theme


class AnimatedScoreWidget(QWidget):
    """Modern animated circular score display with gradient ring."""
    
    score_changed = pyqtSignal(int)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = 0
        self._target_score = 0
        self._risk_level = "No Scan"
        self._grade = "-"
        self._animation = QPropertyAnimation(self, b"animated_score")
        self._animation.setDuration(1500)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.setMinimumSize(220, 220)
        self.setMaximumSize(280, 280)
    
    def get_animated_score(self):
        return self._score
    
    def set_animated_score(self, value):
        self._score = value
        self.update()
    
    animated_score = pyqtProperty(int, get_animated_score, set_animated_score)

    
    def set_score(self, score: int, risk_level: str, grade: str):
        """Animate to new score."""
        self._target_score = max(0, min(100, score))
        self._risk_level = risk_level
        self._grade = grade
        
        self._animation.stop()
        self._animation.setStartValue(self._score)
        self._animation.setEndValue(self._target_score)
        self._animation.start()
        self.score_changed.emit(score)
    
    def reset(self):
        """Reset to default state."""
        self._animation.stop()
        self._score = 0
        self._target_score = 0
        self._risk_level = "No Scan"
        self._grade = "-"
        self.update()
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        center = self.rect().center()
        outer_radius = min(self.width(), self.height()) // 2 - 20
        inner_radius = outer_radius - 15
        
        # Background ring
        bg_pen = QPen(QColor(Theme.SURFACE_LIGHT))
        bg_pen.setWidth(12)
        bg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(bg_pen)
        painter.drawEllipse(center, outer_radius - 6, outer_radius - 6)
        
        # Progress ring with gradient
        if self._score > 0:
            color = QColor(Theme.get_score_color(self._score))
            gradient = QConicalGradient(center, 90)
            gradient.setColorAt(0, color.darker(120))
            gradient.setColorAt(0.5, color)
            gradient.setColorAt(1, color.lighter(120))
            
            progress_pen = QPen(QBrush(gradient), 12)
            progress_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(progress_pen)
            
            span_angle = int(-self._score * 3.6 * 16)
            painter.drawArc(
                QRectF(center.x() - outer_radius + 6, center.y() - outer_radius + 6,
                       (outer_radius - 6) * 2, (outer_radius - 6) * 2),
                90 * 16, span_angle
            )
        
        # Score text
        painter.setPen(QColor(Theme.TEXT_PRIMARY))
        font = QFont(Theme.FONT_FAMILY.split(',')[0].strip('"'))
        font.setPointSize(36)
        font.setBold(True)
        painter.setFont(font)
        score_text = str(self._score)
        metrics = painter.fontMetrics()
        text_rect = metrics.boundingRect(score_text)
        painter.drawText(
            center.x() - text_rect.width() // 2,
            center.y() - 10,
            score_text
        )
        
        # Grade text
        font.setPointSize(14)
        painter.setFont(font)
        painter.setPen(QColor(Theme.get_score_color(self._score) if self._score > 0 else Theme.TEXT_SECONDARY))
        grade_metrics = painter.fontMetrics()
        grade_rect = grade_metrics.boundingRect(self._grade)
        painter.drawText(
            center.x() - grade_rect.width() // 2,
            center.y() + 25,
            self._grade
        )
        
        # Risk level
        font.setPointSize(10)
        painter.setFont(font)
        painter.setPen(QColor(Theme.TEXT_SECONDARY))
        risk_metrics = painter.fontMetrics()
        risk_rect = risk_metrics.boundingRect(self._risk_level)
        painter.drawText(
            center.x() - risk_rect.width() // 2,
            center.y() + 50,
            self._risk_level
        )
        
        painter.end()


class ScoreDisplay(AnimatedScoreWidget):
    """Backward-compatible alias for AnimatedScoreWidget."""
    pass


class SeverityBadge(QWidget):
    """Modern severity badge with icon and count."""
    
    def __init__(self, severity: Severity, count: int = 0, parent=None):
        super().__init__(parent)
        self.severity = severity
        self.count = count
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)
        
        color = Theme.get_severity_color(self.severity.name)
        
        # Icon indicator with glow effect
        self.indicator = QFrame()
        self.indicator.setFixedSize(10, 10)
        self.indicator.setStyleSheet(f"""
            QFrame {{
                background-color: {color};
                border-radius: 5px;
                border: none;
            }}
        """)
        
        # Severity name
        self.name_label = QLabel(self.severity.name)
        self.name_label.setStyleSheet(f"""
            color: {color};
            font-weight: 600;
            font-size: 12px;
        """)
        
        # Count with background
        self.count_label = QLabel(str(self.count))
        self.count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.count_label.setStyleSheet(f"""
            QLabel {{
                background-color: {Theme.SURFACE_LIGHT};
                color: {Theme.TEXT_PRIMARY};
                border-radius: 10px;
                padding: 4px 12px;
                font-weight: 700;
                font-size: 13px;
                min-width: 30px;
            }}
        """)
        
        layout.addWidget(self.indicator)
        layout.addWidget(self.name_label)
        layout.addStretch()
        layout.addWidget(self.count_label)
        
        self.setStyleSheet(f"""
            SeverityBadge {{
                background-color: {Theme.SURFACE};
                border-radius: {Theme.BORDER_RADIUS_NORMAL};
                border: 1px solid {Theme.BORDER};
            }}
            SeverityBadge:hover {{
                background-color: {Theme.SURFACE_LIGHT};
                border-color: {color};
            }}
        """)
    
    def set_count(self, count: int):
        """Update count display."""
        self.count = count
        self.count_label.setText(str(count))


class VulnerabilityItem(QWidget):
    """Modern vulnerability list item with enhanced styling."""
    
    clicked = pyqtSignal(object)
    
    def __init__(self, vulnerability: Vulnerability, parent=None):
        super().__init__(parent)
        self.vulnerability = vulnerability
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)
        
        severity_color = Theme.get_severity_color(self.vulnerability.severity.name)
        
        # Header with severity and title
        header = QHBoxLayout()
        header.setSpacing(12)
        
        # Severity badge (modern pill style)
        self.severity_label = QLabel(self.vulnerability.severity.name)
        self.severity_label.setStyleSheet(f"""
            QLabel {{
                color: {severity_color};
                font-weight: 700;
                font-size: {Theme.FONT_SIZE_XSMALL};
                padding: 4px 10px;
                background-color: {severity_color}20;
                border-radius: {Theme.BORDER_RADIUS_FULL};
                border: 1px solid {severity_color}40;
            }}
        """)
        self.severity_label.setFixedHeight(24)
        
        # Title with better typography
        self.title_label = QLabel(self.vulnerability.title)
        self.title_label.setStyleSheet(f"""
            color: {Theme.TEXT_PRIMARY};
            font-weight: 600;
            font-size: {Theme.FONT_SIZE_NORMAL};
        """)
        self.title_label.setWordWrap(True)
        
        header.addWidget(self.severity_label)
        header.addWidget(self.title_label, 1)
        
        # Location with icon-style prefix
        location_text = self.vulnerability.get_location_string()
        self.location_label = QLabel(f"  {location_text}")
        self.location_label.setStyleSheet(f"""
            color: {Theme.TEXT_TERTIARY};
            font-size: {Theme.FONT_SIZE_SMALL};
            font-family: {Theme.FONT_MONO};
        """)
        
        # Description with better readability
        self.desc_label = QLabel(self.vulnerability.description)
        self.desc_label.setStyleSheet(f"""
            color: {Theme.TEXT_SECONDARY};
            font-size: {Theme.FONT_SIZE_SMALL};
            line-height: 1.5;
        """)
        self.desc_label.setWordWrap(True)
        self.desc_label.setMaximumHeight(50)
        
        layout.addLayout(header)
        layout.addWidget(self.location_label)
        layout.addWidget(self.desc_label)
        
        # Modern card styling with left accent
        self.setStyleSheet(f"""
            VulnerabilityItem {{
                background-color: {Theme.SURFACE};
                border: 1px solid {Theme.BORDER};
                border-left: 4px solid {severity_color};
                border-radius: {Theme.BORDER_RADIUS_NORMAL};
            }}
            VulnerabilityItem:hover {{
                background-color: {Theme.SURFACE_LIGHT};
                border-color: {Theme.BORDER_LIGHT};
                border-left-color: {severity_color};
            }}
        """)
        
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
        # Add subtle shadow
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(8)
        shadow.setColor(QColor(0, 0, 0, 30))
        shadow.setOffset(0, 2)
        self.setGraphicsEffect(shadow)
    
    def enterEvent(self, event):
        """Hover enter effect."""
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(16)
        shadow.setColor(QColor(0, 0, 0, 50))
        shadow.setOffset(0, 4)
        self.setGraphicsEffect(shadow)
        super().enterEvent(event)
    
    def leaveEvent(self, event):
        """Hover leave effect."""
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(8)
        shadow.setColor(QColor(0, 0, 0, 30))
        shadow.setOffset(0, 2)
        self.setGraphicsEffect(shadow)
        super().leaveEvent(event)
    
    def mousePressEvent(self, event):
        """Handle click."""
        self.clicked.emit(self.vulnerability)
        super().mousePressEvent(event)


class VulnerabilityList(QWidget):
    """Modern vulnerability list with enhanced filtering."""
    
    vulnerability_selected = pyqtSignal(object)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.vulnerabilities: List[Vulnerability] = []
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)
        
        # Filter section with modern styling
        filter_container = QFrame()
        filter_container.setStyleSheet(f"""
            QFrame {{
                background-color: {Theme.SURFACE};
                border: 1px solid {Theme.BORDER};
                border-radius: {Theme.BORDER_RADIUS_NORMAL};
                padding: 8px;
            }}
        """)
        filter_layout = QHBoxLayout(filter_container)
        filter_layout.setSpacing(8)
        filter_layout.setContentsMargins(12, 8, 12, 8)
        
        # Filter label
        filter_label = QLabel("Filter by severity:")
        filter_label.setStyleSheet(f"color: {Theme.TEXT_TERTIARY}; font-size: {Theme.FONT_SIZE_SMALL};")
        filter_layout.addWidget(filter_label)
        
        # Modern filter toggles
        self.show_critical = self._create_filter_button("Critical", Theme.CRITICAL)
        self.show_high = self._create_filter_button("High", Theme.HIGH)
        self.show_medium = self._create_filter_button("Medium", Theme.MEDIUM)
        self.show_low = self._create_filter_button("Low", Theme.LOW)
        
        filter_layout.addWidget(self.show_critical)
        filter_layout.addWidget(self.show_high)
        filter_layout.addWidget(self.show_medium)
        filter_layout.addWidget(self.show_low)
        filter_layout.addStretch()
        
        # Results count label
        self.count_label = QLabel("0 issues found")
        self.count_label.setStyleSheet(f"color: {Theme.TEXT_TERTIARY}; font-size: {Theme.FONT_SIZE_SMALL};")
        filter_layout.addWidget(self.count_label)
        
        # List widget with modern styling
        self.list_widget = QListWidget()
        self.list_widget.setSpacing(10)
        self.list_widget.setStyleSheet(f"""
            QListWidget {{
                background-color: {Theme.BACKGROUND};
                border: none;
                padding: 4px;
            }}
            QListWidget::item {{
                background: transparent;
                padding: 0px;
                margin: 4px 0px;
            }}
        """)
        
        layout.addWidget(filter_container)
        layout.addWidget(self.list_widget)
    
    def _create_filter_button(self, text: str, color: str) -> QPushButton:
        """Create a modern filter toggle button."""
        btn = QPushButton(text)
        btn.setCheckable(True)
        btn.setChecked(True)
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {color}20;
                color: {color};
                border: 1px solid {color}40;
                border-radius: {Theme.BORDER_RADIUS_FULL};
                padding: 6px 14px;
                font-size: {Theme.FONT_SIZE_SMALL};
                font-weight: 500;
            }}
            QPushButton:checked {{
                background-color: {color};
                color: {Theme.BACKGROUND};
                border-color: {color};
            }}
            QPushButton:hover:!checked {{
                background-color: {color}30;
                border-color: {color}60;
            }}
        """)
        btn.clicked.connect(self._apply_filter)
        return btn
    
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
        
        # Update count
        total = len(self.vulnerabilities)
        showing = len(filtered)
        self.count_label.setText(f"{showing} of {total} issues")
        
        # Add items
        for vuln in filtered:
            item = QListWidgetItem()
            item.setSizeHint(QSize(0, 110))
            
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
        self.count_label.setText("0 issues found")


class CodePreview(QTextEdit):
    """Modern code preview with enhanced styling."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.setStyleSheet(f"""
            QTextEdit {{
                background-color: {Theme.SURFACE_DARK};
                color: {Theme.TEXT_PRIMARY};
                font-family: {Theme.FONT_MONO};
                font-size: {Theme.FONT_SIZE_SMALL};
                border: 1px solid {Theme.BORDER};
                border-radius: {Theme.BORDER_RADIUS_NORMAL};
                padding: 16px;
                line-height: 1.6;
            }}
        """)
        
        # Add shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(12)
        shadow.setColor(QColor(0, 0, 0, 50))
        shadow.setOffset(0, 3)
        self.setGraphicsEffect(shadow)
    
    def set_code(self, code: str, language: str = "python"):
        """Set code content."""
        self.setPlainText(code)
    
    def clear_code(self):
        """Clear code content."""
        self.clear()


class ModernProgressBar(QProgressBar):
    """Modern animated progress bar."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTextVisible(False)
        self.setFixedHeight(6)
        self.setStyleSheet(f"""
            QProgressBar {{
                background-color: {Theme.SURFACE};
                border: none;
                border-radius: {Theme.BORDER_RADIUS_FULL};
            }}
            QProgressBar::chunk {{
                background-color: {Theme.PRIMARY};
                border-radius: {Theme.BORDER_RADIUS_FULL};
            }}
        """)
        
        # Animation timer for indeterminate state
        self._anim_offset = 0
        self._anim_timer = QTimer(self)
        self._anim_timer.timeout.connect(self._update_animation)
    
    def _update_animation(self):
        """Update animation frame."""
        self._anim_offset = (self._anim_offset + 2) % 100
        gradient = f"""
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {Theme.SURFACE},
                    stop:{self._anim_offset/100} {Theme.PRIMARY},
                    stop:{(self._anim_offset+30)/100} {Theme.PRIMARY_HOVER},
                    stop:{(self._anim_offset+60)/100} {Theme.PRIMARY},
                    stop:1 {Theme.SURFACE});
                border-radius: {Theme.BORDER_RADIUS_FULL};
            }}
        """
        self.setStyleSheet(f"""
            QProgressBar {{
                background-color: {Theme.SURFACE};
                border: none;
                border-radius: {Theme.BORDER_RADIUS_FULL};
            }}
            {gradient}
        """)
    
    def start_animation(self):
        """Start indeterminate animation."""
        self.setRange(0, 0)
        self._anim_timer.start(50)
    
    def stop_animation(self):
        """Stop animation."""
        self._anim_timer.stop()
        self.setStyleSheet(f"""
            QProgressBar {{
                background-color: {Theme.SURFACE};
                border: none;
                border-radius: {Theme.BORDER_RADIUS_FULL};
            }}
            QProgressBar::chunk {{
                background-color: {Theme.PRIMARY};
                border-radius: {Theme.BORDER_RADIUS_FULL};
            }}
        """)


class ProgressWidget(QWidget):
    """Modern progress indicator with status and file info."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self.hide()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(16)
        
        # Modern progress bar
        self.progress_bar = ModernProgressBar()
        self.progress_bar.setFixedWidth(400)
        
        # Status with icon-style prefix
        self.status_label = QLabel("Ready")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet(f"""
            color: {Theme.TEXT_SECONDARY};
            font-size: {Theme.FONT_SIZE_NORMAL};
            font-weight: 500;
        """)
        
        # Current file being scanned
        self.file_label = QLabel("")
        self.file_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.file_label.setStyleSheet(f"""
            color: {Theme.TEXT_TERTIARY};
            font-size: {Theme.FONT_SIZE_SMALL};
            font-family: {Theme.FONT_MONO};
        """)
        self.file_label.hide()
        
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.status_label)
        layout.addWidget(self.file_label)
        
        self.setStyleSheet(f"""
            ProgressWidget {{
                background-color: {Theme.BACKGROUND};
            }}
        """)
    
    def set_status(self, text: str, filename: str = None):
        """Update status text and optional filename."""
        self.status_label.setText(text)
        if filename:
            self.file_label.setText(f"  {filename}")
            self.file_label.show()
        else:
            self.file_label.hide()
    
    def show_progress(self):
        """Show progress widget."""
        self.show()
        self.progress_bar.start_animation()
    
    def hide_progress(self):
        """Hide progress widget."""
        self.hide()
        self.progress_bar.stop_animation()


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
