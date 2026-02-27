"""Dark theme styling constants for SecureMySite GUI."""


class Theme:
    """Dark theme color palette and styling constants."""
    
    # Background colors
    BACKGROUND = '#1a1a1a'
    SURFACE = '#2d2d2d'
    SURFACE_LIGHT = '#3d3d3d'
    SURFACE_DARK = '#151515'
    
    # Primary accent
    PRIMARY = '#00d084'
    PRIMARY_HOVER = '#00e695'
    PRIMARY_DARK = '#00b870'
    
    # Text colors
    TEXT_PRIMARY = '#ffffff'
    TEXT_SECONDARY = '#a0a0a0'
    TEXT_DISABLED = '#666666'
    
    # Border colors
    BORDER = '#3d3d3d'
    BORDER_LIGHT = '#4d4d4d'
    BORDER_FOCUS = '#00d084'
    
    # Severity colors
    CRITICAL = '#ff4444'
    HIGH = '#ff8800'
    MEDIUM = '#ffcc00'
    LOW = '#00ccff'
    INFO = '#a0a0a0'
    
    # Status colors
    SUCCESS = '#00d084'
    WARNING = '#ffcc00'
    ERROR = '#ff4444'
    
    # Score gradient colors
    SCORE_EXCELLENT = '#00d084'  # 80-100
    SCORE_GOOD = '#88cc00'       # 60-79
    SCORE_WARNING = '#ff8800'    # 40-59
    SCORE_CRITICAL = '#ff4444'   # 0-39
    
    # Typography
    FONT_FAMILY = 'Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif'
    FONT_SIZE_SMALL = '11px'
    FONT_SIZE_NORMAL = '13px'
    FONT_SIZE_LARGE = '15px'
    FONT_SIZE_TITLE = '18px'
    FONT_SIZE_HEADER = '24px'
    
    # Spacing
    PADDING_SMALL = '4px'
    PADDING_NORMAL = '8px'
    PADDING_LARGE = '16px'
    PADDING_XLARGE = '24px'
    
    # Border radius
    BORDER_RADIUS_SMALL = '4px'
    BORDER_RADIUS_NORMAL = '6px'
    BORDER_RADIUS_LARGE = '8px'
    
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
    def get_stylesheet(cls) -> str:
        """Get complete application stylesheet."""
        return f"""
        QMainWindow {{
            background-color: {cls.BACKGROUND};
            color: {cls.TEXT_PRIMARY};
            font-family: {cls.FONT_FAMILY};
            font-size: {cls.FONT_SIZE_NORMAL};
        }}
        
        QWidget {{
            background-color: {cls.BACKGROUND};
            color: {cls.TEXT_PRIMARY};
            font-family: {cls.FONT_FAMILY};
        }}
        
        QPushButton {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            padding: {cls.PADDING_NORMAL} {cls.PADDING_LARGE};
            font-size: {cls.FONT_SIZE_NORMAL};
        }}
        
        QPushButton:hover {{
            background-color: {cls.SURFACE_LIGHT};
            border-color: {cls.BORDER_LIGHT};
        }}
        
        QPushButton:pressed {{
            background-color: {cls.SURFACE_DARK};
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
            font-weight: bold;
        }}
        
        QPushButton#primaryButton:hover {{
            background-color: {cls.PRIMARY_HOVER};
        }}
        
        QLineEdit {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            padding: {cls.PADDING_NORMAL};
        }}
        
        QLineEdit:focus {{
            border-color: {cls.BORDER_FOCUS};
        }}
        
        QTextEdit {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            padding: {cls.PADDING_NORMAL};
        }}
        
        QListWidget {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            outline: none;
        }}
        
        QListWidget::item {{
            padding: {cls.PADDING_NORMAL};
            border-bottom: 1px solid {cls.BORDER};
        }}
        
        QListWidget::item:selected {{
            background-color: {cls.SURFACE_LIGHT};
            border-left: 3px solid {cls.PRIMARY};
        }}
        
        QListWidget::item:hover {{
            background-color: {cls.SURFACE_LIGHT};
        }}
        
        QScrollBar:vertical {{
            background-color: {cls.SURFACE};
            width: 12px;
            border-radius: {cls.BORDER_RADIUS_SMALL};
        }}
        
        QScrollBar::handle:vertical {{
            background-color: {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_SMALL};
            min-height: 20px;
        }}
        
        QScrollBar::handle:vertical:hover {{
            background-color: {cls.BORDER_LIGHT};
        }}
        
        QLabel {{
            color: {cls.TEXT_PRIMARY};
        }}
        
        QLabel#titleLabel {{
            font-size: {cls.FONT_SIZE_TITLE};
            font-weight: bold;
        }}
        
        QLabel#subtitleLabel {{
            font-size: {cls.FONT_SIZE_LARGE};
            color: {cls.TEXT_SECONDARY};
        }}
        
        QGroupBox {{
            background-color: {cls.SURFACE};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            margin-top: 12px;
            padding-top: 12px;
            font-weight: bold;
        }}
        
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 8px;
        }}
        
        QProgressBar {{
            background-color: {cls.SURFACE};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            text-align: center;
            color: {cls.TEXT_PRIMARY};
        }}
        
        QProgressBar::chunk {{
            background-color: {cls.PRIMARY};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
        }}
        
        QComboBox {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
            border-radius: {cls.BORDER_RADIUS_NORMAL};
            padding: {cls.PADDING_NORMAL};
        }}
        
        QComboBox::drop-down {{
            border: none;
            width: 20px;
        }}
        
        QComboBox QAbstractItemView {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
            selection-background-color: {cls.SURFACE_LIGHT};
        }}
        
        QMenuBar {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
        }}
        
        QMenuBar::item:selected {{
            background-color: {cls.SURFACE_LIGHT};
        }}
        
        QMenu {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
        }}
        
        QMenu::item:selected {{
            background-color: {cls.SURFACE_LIGHT};
        }}
        
        QStatusBar {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_SECONDARY};
        }}
        
        QToolTip {{
            background-color: {cls.SURFACE};
            color: {cls.TEXT_PRIMARY};
            border: 1px solid {cls.BORDER};
            padding: {cls.PADDING_NORMAL};
        }}
        """
