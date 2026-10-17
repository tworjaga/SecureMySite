"""Dark theme (slate + indigo) for the SecureMySite GUI."""


class Theme:
    """Color palette, typography and the application stylesheet."""

    # Backgrounds (darkest -> lightest)
    BACKGROUND = '#0b0f19'
    SIDEBAR = '#0e1422'
    SURFACE = '#131a2a'
    SURFACE_LIGHT = '#1a2336'
    SURFACE_LIGHTER = '#222d44'
    SURFACE_DARK = '#090c14'

    # Borders
    BORDER = '#222c42'
    BORDER_LIGHT = '#2f3b57'

    # Accent (indigo / periwinkle)
    PRIMARY = '#7c8cff'
    PRIMARY_HOVER = '#97a4ff'
    PRIMARY_DARK = '#6574f0'
    PRIMARY_SOFT = '#7c8cff'  # used with rgba()
    ON_PRIMARY = '#0b0f19'

    # Text
    TEXT_PRIMARY = '#e8ecf5'
    TEXT_SECONDARY = '#a4aec4'
    TEXT_TERTIARY = '#6c7791'
    TEXT_DISABLED = '#4a5470'

    # Severity
    CRITICAL = '#ff5c7a'
    HIGH = '#ff9a52'
    MEDIUM = '#f2c94c'
    LOW = '#56c2f0'

    # Status
    SUCCESS = '#3ddc97'
    WARNING = '#f2c94c'
    ERROR = '#ff5c7a'

    # Score bands
    SCORE_EXCELLENT = '#3ddc97'   # 80-100
    SCORE_GOOD = '#a3d65c'        # 60-79
    SCORE_WARNING = '#ff9a52'     # 40-59
    SCORE_CRITICAL = '#ff5c7a'    # 0-39

    # Typography
    FONT_FAMILY = '"Segoe UI", "Inter", "SF Pro Text", "Helvetica Neue", Arial, sans-serif'
    FONT_MONO = '"Cascadia Mono", "JetBrains Mono", "Fira Code", Consolas, monospace'
    FONT_SIZE_XSMALL = '10px'
    FONT_SIZE_SMALL = '12px'
    FONT_SIZE_NORMAL = '13px'
    FONT_SIZE_LARGE = '15px'

    BORDER_RADIUS_SMALL = '6px'
    BORDER_RADIUS_NORMAL = '8px'
    BORDER_RADIUS_LARGE = '12px'
    BORDER_RADIUS_FULL = '999px'

    @staticmethod
    def rgba(hex_color: str, alpha_percent: int) -> str:
        """'#rrggbb' + opacity percent -> 'rgba(r, g, b, a)' (Qt reads #rrggbbaa as #aarrggbb)."""
        h = hex_color.lstrip('#')
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        return f"rgba({r}, {g}, {b}, {alpha_percent / 100:.2f})"

    @classmethod
    def get_severity_color(cls, severity: str) -> str:
        return {
            'CRITICAL': cls.CRITICAL,
            'HIGH': cls.HIGH,
            'MEDIUM': cls.MEDIUM,
            'LOW': cls.LOW,
        }.get(str(severity).upper(), cls.TEXT_TERTIARY)

    @classmethod
    def get_score_color(cls, score: int) -> str:
        if score >= 80:
            return cls.SCORE_EXCELLENT
        if score >= 60:
            return cls.SCORE_GOOD
        if score >= 40:
            return cls.SCORE_WARNING
        return cls.SCORE_CRITICAL

    @classmethod
    def get_stylesheet(cls) -> str:
        c = cls
        return f"""
        QWidget {{
            background-color: {c.BACKGROUND};
            color: {c.TEXT_PRIMARY};
            font-family: {c.FONT_FAMILY};
            font-size: {c.FONT_SIZE_NORMAL};
        }}
        QLabel {{ background: transparent; }}
        QToolTip {{
            background-color: {c.SURFACE_LIGHTER};
            color: {c.TEXT_PRIMARY};
            border: 1px solid {c.BORDER_LIGHT};
            padding: 6px 8px;
            border-radius: 6px;
        }}

        /* Menus */
        QMenuBar {{ background-color: {c.SIDEBAR}; border-bottom: 1px solid {c.BORDER}; padding: 2px 6px; }}
        QMenuBar::item {{ background: transparent; padding: 6px 10px; border-radius: 6px; color: {c.TEXT_SECONDARY}; }}
        QMenuBar::item:selected {{ background-color: {c.SURFACE_LIGHT}; color: {c.TEXT_PRIMARY}; }}
        QMenu {{ background-color: {c.SURFACE}; border: 1px solid {c.BORDER_LIGHT}; padding: 6px; border-radius: 8px; }}
        QMenu::item {{ padding: 7px 24px 7px 12px; border-radius: 6px; background: transparent; }}
        QMenu::item:selected {{ background-color: {cls.rgba(c.PRIMARY, 18)}; color: {c.TEXT_PRIMARY}; }}
        QMenu::separator {{ height: 1px; background: {c.BORDER}; margin: 6px 4px; }}

        /* Inputs */
        QLineEdit, QComboBox {{
            background-color: {c.SURFACE_DARK};
            color: {c.TEXT_PRIMARY};
            border: 1px solid {c.BORDER};
            border-radius: {c.BORDER_RADIUS_NORMAL};
            padding: 7px 10px;
            selection-background-color: {c.PRIMARY_DARK};
        }}
        QLineEdit:focus, QComboBox:focus {{ border-color: {c.PRIMARY}; }}
        QLineEdit:hover, QComboBox:hover {{ border-color: {c.BORDER_LIGHT}; }}
        QComboBox::drop-down {{ border: none; width: 22px; }}
        QComboBox QAbstractItemView {{
            background-color: {c.SURFACE};
            border: 1px solid {c.BORDER_LIGHT};
            selection-background-color: {cls.rgba(c.PRIMARY, 22)};
            outline: none;
        }}

        QCheckBox {{ spacing: 8px; color: {c.TEXT_SECONDARY}; background: transparent; }}
        QCheckBox::indicator {{
            width: 16px; height: 16px; border-radius: 4px;
            border: 1px solid {c.BORDER_LIGHT}; background: {c.SURFACE_DARK};
        }}
        QCheckBox::indicator:hover {{ border-color: {c.PRIMARY}; }}
        QCheckBox::indicator:checked {{ background: {c.PRIMARY}; border-color: {c.PRIMARY}; }}

        /* Buttons */
        QPushButton, QToolButton {{
            background-color: {c.SURFACE_LIGHT};
            color: {c.TEXT_PRIMARY};
            border: 1px solid {c.BORDER_LIGHT};
            border-radius: {c.BORDER_RADIUS_NORMAL};
            padding: 7px 14px;
            font-weight: 500;
        }}
        QPushButton:hover, QToolButton:hover {{ background-color: {c.SURFACE_LIGHTER}; border-color: {c.PRIMARY}; }}
        QPushButton:pressed, QToolButton:pressed {{ background-color: {c.SURFACE}; }}
        QPushButton:disabled, QToolButton:disabled {{
            color: {c.TEXT_DISABLED}; border-color: {c.BORDER}; background-color: {c.SURFACE};
        }}
        QToolButton::menu-indicator {{ image: none; width: 0; }}
        QPushButton#primaryButton {{
            background-color: {c.PRIMARY};
            color: {c.ON_PRIMARY};
            border: none;
            font-weight: 700;
            padding: 10px 16px;
        }}
        QPushButton#primaryButton:hover {{ background-color: {c.PRIMARY_HOVER}; }}
        QPushButton#primaryButton:pressed {{ background-color: {c.PRIMARY_DARK}; }}
        QPushButton#primaryButton:disabled {{ background-color: {c.SURFACE_LIGHTER}; color: {c.TEXT_DISABLED}; }}
        QPushButton#dangerButton {{
            background-color: {cls.rgba(c.CRITICAL, 16)}; color: {c.CRITICAL}; border: 1px solid {cls.rgba(c.CRITICAL, 45)};
            font-weight: 700; padding: 10px 16px;
        }}

        /* Panels */
        QFrame#sidebar {{ background-color: {c.SIDEBAR}; border-right: 1px solid {c.BORDER}; }}
        QFrame#sidebar QWidget {{ background-color: transparent; }}
        QFrame#sidebar QLineEdit, QFrame#sidebar QComboBox {{ background-color: {c.SURFACE_DARK}; }}
        QFrame#sidebar QPushButton, QFrame#sidebar QToolButton {{ background-color: {c.SURFACE_LIGHT}; }}
        QFrame#sidebar QPushButton#primaryButton {{ background-color: {c.PRIMARY}; }}
        QFrame#sidebar QPushButton#primaryButton:hover {{ background-color: {c.PRIMARY_HOVER}; }}
        QFrame#sidebar QPushButton#dangerButton {{ background-color: {cls.rgba(c.CRITICAL, 16)}; }}
        QFrame#card {{
            background-color: {c.SURFACE};
            border: 1px solid {c.BORDER};
            border-radius: {c.BORDER_RADIUS_LARGE};
        }}
        QFrame#card QWidget {{ background-color: transparent; }}
        QLabel#sectionLabel {{
            color: {c.TEXT_TERTIARY}; font-size: 11px; font-weight: 700; letter-spacing: 1px;
        }}
        QLabel#cardTitle {{ color: {c.TEXT_SECONDARY}; font-size: 12px; font-weight: 600; }}
        QLabel#muted {{ color: {c.TEXT_TERTIARY}; font-size: 12px; }}

        /* Tabs */
        QTabWidget::pane {{ border: none; border-top: 1px solid {c.BORDER}; background: transparent; top: -1px; }}
        QTabWidget::tab-bar {{ left: 0px; }}
        QTabBar {{ background: transparent; qproperty-drawBase: 0; }}
        QTabBar::tab {{
            background: transparent; color: {c.TEXT_TERTIARY};
            padding: 9px 16px; margin-right: 4px; border: none;
            border-bottom: 2px solid transparent; font-weight: 600;
        }}
        QTabBar::tab:hover {{ color: {c.TEXT_SECONDARY}; }}
        QTabBar::tab:selected {{ color: {c.TEXT_PRIMARY}; border-bottom: 2px solid {c.PRIMARY}; }}

        /* Tables / trees */
        QTreeWidget, QTableWidget, QTextBrowser, QPlainTextEdit {{
            background-color: {c.SURFACE};
            alternate-background-color: {c.SURFACE_LIGHT};
            border: 1px solid {c.BORDER};
            border-radius: {c.BORDER_RADIUS_LARGE};
            gridline-color: {c.BORDER};
            outline: none;
        }}
        QTreeWidget::item, QTableWidget::item {{ padding: 6px 4px; border: none; }}
        QTreeWidget::item:selected, QTableWidget::item:selected {{
            background-color: {cls.rgba(c.PRIMARY, 20)}; color: {c.TEXT_PRIMARY};
        }}
        QTreeWidget::item:hover, QTableWidget::item:hover {{ background-color: {c.SURFACE_LIGHTER}; }}
        QHeaderView::section {{
            background-color: {c.SURFACE};
            color: {c.TEXT_TERTIARY};
            border: none;
            border-bottom: 1px solid {c.BORDER};
            padding: 8px 6px;
            font-size: 11px;
            font-weight: 700;
        }}

        /* Scrollbars */
        QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
        QScrollBar::handle:vertical {{ background: {c.BORDER_LIGHT}; border-radius: 4px; min-height: 30px; }}
        QScrollBar::handle:vertical:hover {{ background: {c.TEXT_TERTIARY}; }}
        QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
        QScrollBar::handle:horizontal {{ background: {c.BORDER_LIGHT}; border-radius: 4px; min-width: 30px; }}
        QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
        QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}

        QSplitter::handle {{ background: transparent; }}
        QSplitter::handle:horizontal {{ width: 8px; }}

        QProgressBar {{
            background-color: {c.SURFACE_LIGHT}; border: none; border-radius: 3px; max-height: 6px;
        }}
        QProgressBar::chunk {{ background-color: {c.PRIMARY}; border-radius: 3px; }}

        QStatusBar {{ background-color: {c.SIDEBAR}; color: {c.TEXT_TERTIARY}; border-top: 1px solid {c.BORDER}; }}
        QStatusBar::item {{ border: none; }}

        QDialog {{ background-color: {c.BACKGROUND}; }}
        QMessageBox QLabel {{ color: {c.TEXT_PRIMARY}; }}
        """
