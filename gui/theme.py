"""Modern dark theme styling for SecureMySite GUI."""

from typing import Optional


class Theme:
    """Modern dark theme with glassmorphism and elegant styling."""
    
    # Deep dark background palette
    BACKGROUND = '#0d0d0d'
    BACKGROUND_ELEVATED = '#141414'
    SURFACE = '#1a1a1a'
    SURFACE_LIGHT = '#252525'
    SURFACE_LIGHTER = '#2d2d2d'
    SURFACE_DARK = '#0f0f0f'
    
    # Glassmorphism effects
    GLASS_BG = 'rgba(26, 26, 26, 0.85)'
    GLASS_BORDER = 'rgba(255, 255, 255, 0.08)'
    GLASS_HIGHLIGHT = 'rgba(255, 255, 255, 0.05)'
    
    # Modern accent colors (cyan/mint gradient)
    PRIMARY = '#00d4aa'
    PRIMARY_HOVER = '#00f5c4'
    PRIMARY_DARK = '#00b894'
    PRIMARY_GLOW = 'rgba(0, 212, 170, 0.3)'
    
    # Secondary accents
    ACCENT_CYAN = '#00d4ff'
    ACCENT_PURPLE = '#a855f7'
    ACCENT_BLUE = '#3b82f6'
    ACCENT_PINK = '#ec4899'
    
    # Text colors with better contrast
    TEXT_PRIMARY = '#f8fafc'
    TEXT_SECONDARY = '#94a3b8'
    TEXT_TERTIARY = '#64748b'
    TEXT_DISABLED = '#475569'
    
    # Border colors
    BORDER = 'rgba(255, 255, 255, 0.08)'
    BORDER_LIGHT = 'rgba(255, 255, 255, 0.12)'
    BORDER_FOCUS = '#00d4aa'
    BORDER_GLOW = 'rgba(0, 212, 170, 0.4)'
    
    # Severity colors (modern vibrant palette)
    CRITICAL = '#ef4444'
    HIGH = '#f97316'
    MEDIUM = '#eab308'
    LOW = '#06b6d4'
    INFO = '#64748b'
    
    # Status colors
    SUCCESS = '#10b981'
    WARNING = '#f59e0b'
    ERROR = '#ef4444'
    
    # Score gradient colors (modern)
    SCORE_EXCELLENT = '#10b981'  # 80-100
    SCORE_GOOD = '#84cc16'       # 60-79
    SCORE_WARNING = '#f59e0b'      # 40-59
    SCORE_CRITICAL = '#ef4444'   # 0-39
    
    # Typography (modern system fonts)
    FONT_FAMILY = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
    FONT_MONO = '"JetBrains Mono", "Fira Code", "Consolas", monospace'
    
    FONT_SIZE_XSMALL = '10px'
    FONT_SIZE_SMALL = '12px'
    FONT_SIZE_NORMAL = '14px'
    FONT_SIZE_LARGE = '16px'
    FONT_SIZE_XLARGE = '18px'
    FONT_SIZE_TITLE = '20px'
    FONT_SIZE_HEADER = '28px'
    FONT_SIZE_DISPLAY = '48px'
    
    # Spacing (8px grid system)
    PADDING_XSMALL = '4px'
    PADDING_SMALL = '8px'
    PADDING_NORMAL = '12px'
    PADDING_LARGE = '16px'
    PADDING_XLARGE = '24px'
    PADDING_XXLARGE = '32px'
    
    # Border radius (modern rounded corners)
    BORDER_RADIUS_SMALL = '6px'
    BORDER_RADIUS_NORMAL = '10px'
    BORDER_RADIUS_LARGE = '14px'
    BORDER_RADIUS_XLARGE = '20px'
    BORDER_RADIUS_FULL = '9999px'
    
    # Shadows for depth
    SHADOW_SMALL = '0 1px 2px rgba(0, 0, 0, 0.3)'
    SHADOW_NORMAL = '0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -1px rgba(0, 0, 0, 0.2)'
    SHADOW_LARGE = '0 10px 15px -3px rgba(0, 0, 0, 0.5), 0 4px 6px -2px rgba(0, 0, 0, 0.3)'
    SHADOW_GLOW = '0 0 20px rgba(0, 212, 170, 0.15)'
    SHADOW_GLOW_INTENSE = '0 0 30px rgba(0, 212, 170, 0.25)'
    
    # Transitions
    TRANSITION_FAST = '150ms ease'
    TRANSITION_NORMAL = '250ms ease'
    TRANSITION_SLOW = '350ms ease'
    
    @classmethod
    def get_score_color(cls, score: int) -> str:
        """Get color for security score."""
        if score >= 80:
            return cls.SCORE_EXCELLENT
        elif score >= 60:
            return cls.SCORE_GOOD
        elif score >= 40:
            return cls.SCORE_WARNING
        else:
            return cls.SCORE_CRITICAL
    
    @classmethod
    def get_score_gradient(cls, score: int) -> str:
        """Get gradient for security score."""
        if score >= 80:
            return f'linear-gradient(135deg, {cls.SCORE_EXCELLENT}, #34d399)'
        elif score >= 60:
            return f'linear-gradient(135deg, {cls.SCORE_GOOD}, #a3e635)'
        elif score >= 40:
            return f'linear-gradient(135deg, {cls.SCORE_WARNING}, #fbbf24)'
        else:
            return f'linear-gradient(135deg, {cls.SCORE_CRITICAL}, #f87171)'
    
    @classmethod
    def get_severity_color(cls, severity: str) -> str:
        """Get color for severity level."""
        severity_map = {
            'CRITICAL': cls.CRITICAL,
            'HIGH': cls.HIGH,
            'MEDIUM': cls.MEDIUM,
            'LOW': cls.LOW,
        }
        return severity_map.get(severity.upper(), cls.INFO)
    
    @classmethod
    def get_glassmorphism_style(cls, border_radius: str = None) -> str:
        """Get glassmorphism CSS style."""
        radius = border_radius or cls.BORDER_RADIUS_NORMAL
        return f"""
            background-color: {cls.GLASS_BG};
            border: 1px solid {cls.GLASS_BORDER};
            border-radius: {radius};
        """
    
    @classmethod
    def get_card_style(cls, elevated: bool = False) -> str:
        """Get modern card style."""
        shadow = cls.SHADOW_LARGE if elevated else cls.SHADOW_NORMAL
        return f"""
            background-color: {cls.SURFACE};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_LARGE};
            box-shadow: {shadow};
        """
    
    @classmethod
    def get_stylesheet(cls) -> str:
        """Get complete modern application stylesheet."""
        return f"""
        /* Main Window */
        QMainWindow {{
            background-color: {cls.BACKGROUND};
            color: {cls.TEXT_PRIMARY};
            font-family: {cls.FONT_FAMILY};
            font-size: {cls.FONT_SIZE_NORMAL};
        }}
        
        /* Base Widget */
        QWidget {{
            background-color: {cls.BACKGROUND};
            color: {cls.TEXT_PRIMARY};
            font-family: {cls.FONT_FAMILY};
        }}
        
        /* Modern Buttons */
        QPushButton {{
            background-color: {cls.SURFACE_LIGHT};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            padding: {cls.PADDING_NORMAL} {cls.PADDING_LARGE};
            font-size: {cls.FONT_SIZE_NORMAL};
            font-weight: 500;
        }}
        
        QPushButton:hover {{
            background-color: {cls.SURFACE_LIGHTER};
            border-color: {cls.BORDER_LIGHT};
        }}
        
        QPushButton:pressed {{
            background-color: {cls.SURFACE};
        }}
        
        QPushButton:disabled {{
            background-color: {cls.SURFACE_DARK};
            color: {cls.TEXT_DISABLED};
            border-color: {cls.BORDER};
        }}
        
        QPushButton#primaryButton {{
            background-color: {cls.PRIMARY};
            color: {cls.BACKGROUND};
            border: none;
            font-weight: 600;
        }}
        
        QPushButton#primaryButton:hover {{
            background-color: {cls.PRIMARY_HOVER};
            box-shadow: {cls.SHADOW_GLOW};
        }}
        
        QPushButton#secondaryButton {{
            background-color: transparent;
            color: {cls.PRIMARY};
            border: 1px solid {cls.PRIMARY};
        }}
        
        QPushButton#secondaryButton:hover {{
            background-color: {cls.PRIMARY_GLOW};
        }}
        
        QPushButton#iconButton {{
            background-color: transparent;
            border: none;
            border-radius: {cls.BORDER_RADIUS_SMALL};
            padding: {cls.PADDING_SMALL};
        }}
        
        QPushButton#iconButton:hover {{
            background-color: {cls.SURFACE_LIGHT};
        }}
        
        /* Modern Inputs */
        QLineEdit {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            padding: {cls.PADDING_NORMAL} {cls.PADDING_LARGE};
            font-size: {cls.FONT_SIZE_NORMAL};
        }}
        
        QLineEdit:focus {{
            border-color: {cls.BORDER_FOCUS};
            background-color: {cls.SURFACE_LIGHT};
        }}
        
        QLineEdit:hover {{
            border-color: {cls.BORDER_LIGHT};
        }}
        
        /* Text Edit */
        QTextEdit {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            padding: {cls.PADDING_NORMAL};
            font-family: {cls.FONT_MONO};
            font-size: {cls.FONT_SIZE_SMALL};
        }}
        
        QTextEdit:focus {{
            border-color: {cls.BORDER_FOCUS};
        }}
        
        /* List Widget */
        QListWidget {{
            background-color: {cls.BACKGROUND};
            color: {cls.TEXT_PRIMARY};
            border: none;
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            outline: none;
            padding: {cls.PADDING_SMALL};
        }}
        
        QListWidget::item {{
            background: transparent;
            border-radius: {cls.BORDER_RADIUS_SMALL};
            margin: 2px 0px;
            padding: 0px;
        }}
        
        QListWidget::item:selected {{
            background-color: transparent;
        }}
        
        /* Scrollbars */
        QScrollBar:vertical {{
            background-color: transparent;
            width: 8px;
            border-radius: 4px;
            margin: 4px;
        }}
        
        QScrollBar::handle:vertical {{
            background-color: {cls.BORDER};
            border-radius: 4px;
            min-height: 32px;
        }}
        
        QScrollBar::handle:vertical:hover {{
            background-color: {cls.TEXT_TERTIARY};
        }}
        
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
        
        QScrollBar:horizontal {{
            background-color: transparent;
            height: 8px;
            border-radius: 4px;
            margin: 4px;
        }}
        
        QScrollBar::handle:horizontal {{
            background-color: {cls.BORDER};
            border-radius: 4px;
            min-width: 32px;
        }}
        
        QScrollBar::handle:horizontal:hover {{
            background-color: {cls.TEXT_TERTIARY};
        }}
        
        /* Labels */
        QLabel {{
            color: {cls.TEXT_PRIMARY};
        }}
        
        QLabel#titleLabel {{
            font-size: {cls.FONT_SIZE_HEADER};
            font-weight: 700;
            color: {cls.TEXT_PRIMARY};
        }}
        
        QLabel#subtitleLabel {{
            font-size: {cls.FONT_SIZE_LARGE};
            color: {cls.TEXT_SECONDARY};
            font-weight: 400;
        }}
        
        QLabel#captionLabel {{
            font-size: {cls.FONT_SIZE_SMALL};
            color: {cls.TEXT_TERTIARY};
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        QLabel#metricLabel {{
            font-size: {cls.FONT_SIZE_DISPLAY};
            font-weight: 700;
        }}
        
        /* Group Box (Card Style) */
        QGroupBox {{
            background-color: {cls.SURFACE};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_LARGE};
            margin-top: 16px;
            padding-top: 16px;
            padding: {cls.PADDING_XLARGE};
            font-weight: 600;
            font-size: {cls.FONT_SIZE_LARGE};
        }}
        
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: {cls.PADDING_XLARGE};
            padding: 0 {cls.PADDING_SMALL};
            color: {cls.TEXT_PRIMARY};
        }}
        
        /* Progress Bar */
        QProgressBar {{
            background-color: {cls.SURFACE};
            border: none;
            border-radius: {cls.BORDER_RADIUS_FULL};
            text-align: center;
            color: transparent;
            height: 6px;
        }}
        
        QProgressBar::chunk {{
            background-color: {cls.PRIMARY};
            border-radius: {cls.BORDER_RADIUS_FULL};
        }}
        
        /* Combo Box */
        QComboBox {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            padding: {cls.PADDING_NORMAL} {cls.PADDING_LARGE};
            min-width: 100px;
        }}
        
        QComboBox:hover {{
            border-color: {cls.BORDER_LIGHT};
        }}
        
        QComboBox::drop-down {{
            border: none;
            width: 24px;
        }}
        
        QComboBox QAbstractItemView {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            selection-background-color: {cls.SURFACE_LIGHT};
            padding: {cls.PADDING_SMALL};
        }}
        
        /* Menu */
        QMenuBar {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
            border-bottom: 1px solid {cls.BORDER};
            padding: 4px;
        }}
        
        QMenuBar::item {{
            background-color: transparent;
            border-radius: {cls.BORDER_RADIUS_SMALL};
            padding: 6px 12px;
        }}
        
        QMenuBar::item:selected {{
            background-color: {cls.SURFACE_LIGHT};
        }}
        
        QMenu {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            padding: {cls.PADDING_SMALL};
        }}
        
        QMenu::item {{
            padding: 8px 24px;
            border-radius: {cls.BORDER_RADIUS_SMALL};
        }}
        
        QMenu::item:selected {{
            background-color: {cls.SURFACE_LIGHT};
        }}
        
        QMenu::separator {{
            height: 1px;
            background-color: {cls.BORDER};
            margin: 8px 0px;
        }}
        
        /* Status Bar */
        QStatusBar {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_SECONDARY};
            border-top: 1px solid {cls.BORDER};
        }}
        
        QStatusBar::item {{
            border: none;
        }}
        
        /* Tool Tip */
        QToolTip {{
            background-color: {cls.SURFACE_LIGHT};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_SMALL};
            padding: {cls.PADDING_NORMAL} {cls.PADDING_LARGE};
            font-size: {cls.FONT_SIZE_SMALL};
        }}
        
        /* Splitter */
        QSplitter::handle {{
            background-color: {cls.BORDER};
        }}
        
        QSplitter::handle:horizontal {{
            width: 2px;
        }}
        
        QSplitter::handle:vertical {{
            height: 2px;
        }}
        
        /* Check Box */
        QCheckBox {{
            color: {cls.TEXT_PRIMARY};
            spacing: 8px;
        }}
        
        QCheckBox::indicator {{
            width: 18px;
            height: 18px;
            border-radius: 4px;
            border: 1px solid {cls.BORDER};
            background-color: {cls.SURFACE};
        }}
        
        QCheckBox::indicator:checked {{
            background-color: {cls.PRIMARY};
            border-color: {cls.PRIMARY};
        }}
        
        /* Radio Button */
        QRadioButton {{
            color: {cls.TEXT_PRIMARY};
            spacing: 8px;
        }}
        
        QRadioButton::indicator {{
            width: 18px;
            height: 18px;
            border-radius: 9px;
            border: 1px solid {cls.BORDER};
            background-color: {cls.SURFACE};
        }}
        
        QRadioButton::indicator:checked {{
            background-color: {cls.PRIMARY};
            border-color: {cls.PRIMARY};
        }}
        
        /* Tab Widget */
        QTabWidget::pane {{
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            background-color: {cls.SURFACE};
        }}
        
        QTabBar::tab {{
            background-color: transparent;
            color: {cls.TEXT_SECONDARY};
            padding: 12px 24px;
            border: none;
            border-bottom: 2px solid transparent;
        }}
        
        QTabBar::tab:selected {{
            color: {cls.PRIMARY};
            border-bottom-color: {cls.PRIMARY};
        }}
        
        QTabBar::tab:hover {{
            color: {cls.TEXT_PRIMARY};
        }}
        
        /* Frame */
        QFrame {{
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
        }}
        
        QFrame#cardFrame {{
            background-color: {cls.SURFACE};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_LARGE};
        }}
        
        QFrame#glassFrame {{
            background-color: {cls.GLASS_BG};
            border: 1px solid {cls.GLASS_BORDER};
            border-radius: {cls.BORDER_RADIUS_LARGE};
        }}
        """
