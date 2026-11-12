from string import Template

from PySide6.QtWidgets import QApplication, QWidget

BG = "#0A0A0F"
SIDEBAR = "#0E0E15"
SURFACE = "#14141C"
SURFACE_2 = "#1D1D29"
BORDER = "#2A2A3A"
TEXT = "#F5F5FA"
MUTED = "#8E8EA3"
DIM = "#5D5D72"
PINK = "#FF3D7F"
CYAN = "#25F4EE"
GREEN = "#3DFFA2"
AMBER = "#FFC83D"
RED = "#FF4D6D"

_FONT = '"Inter", "SF Pro Display", "Segoe UI Variable Display", "Segoe UI", "Roboto", "Noto Sans", sans-serif'
_MONO = '"Cascadia Mono", "SF Mono", "Consolas", "Menlo", monospace'

_QSS = """
* { font-family: $FONT; color: $TEXT; font-size: 14px; }
QMainWindow, #root { background: $BG; }
QLabel { background: transparent; }
QToolTip { background: $SURFACE_2; color: $TEXT; border: 1px solid $BORDER; padding: 6px 8px; }

#sidebar { background: $SIDEBAR; border-right: 1px solid $BORDER; }
#logo { font-size: 22px; font-weight: 800; }
#tagline, #version { color: $DIM; font-size: 12px; }

QPushButton#nav {
    text-align: left; padding: 13px 16px; border: none; border-radius: 14px;
    background: transparent; color: $MUTED; font-size: 15px; font-weight: 600;
}
QPushButton#nav[ready="false"] { color: $DIM; }
QPushButton#nav:hover { background: $SURFACE; color: $TEXT; }
QPushButton#nav:checked {
    color: $TEXT;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(255,61,127,60), stop:1 rgba(37,244,238,40));
}

#h1 { font-size: 30px; font-weight: 800; }
#h2 { font-size: 20px; font-weight: 700; }
#sub { color: $MUTED; font-size: 15px; }
#small { color: $MUTED; font-size: 12px; }
#bigemoji { font-size: 56px; }

#dropzone { background: $SURFACE; border: 2px dashed #3A3A52; border-radius: 28px; }
#dropzone[hover="true"] { background: #101D24; border: 2px dashed $CYAN; }
#dropicon { font-size: 64px; }
#droptitle { font-size: 24px; font-weight: 800; }
#busy { background: $SURFACE; border: 1px solid $BORDER; border-radius: 28px; }

#banner {
    background: rgba(255,77,109,40); border: 1px solid rgba(255,77,109,140);
    border-radius: 14px;
}

#resultcard { background: $SURFACE; border: 1px solid $BORDER; border-radius: 28px; }
#resultcard[tone="safe"] {
    border: 1px solid rgba(61,255,162,120);
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(61,255,162,30), stop:1 $SURFACE);
}
#resultcard[tone="suspicious"] {
    border: 1px solid rgba(255,200,61,130);
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,200,61,30), stop:1 $SURFACE);
}
#resultcard[tone="dangerous"] {
    border: 1px solid rgba(255,77,109,150);
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,77,109,38), stop:1 $SURFACE);
}
#reasons { font-size: 15px; }
#callout { background: $SURFACE_2; border-radius: 16px; }
#callout QLabel { font-size: 15px; }
#notice {
    background: rgba(255,200,61,30); border: 1px solid rgba(255,200,61,110);
    border-radius: 14px;
}
#notice QLabel { color: $AMBER; }
#details { background: $SIDEBAR; border-radius: 14px; }
#details QLabel { color: $MUTED; font-family: $MONO; font-size: 12px; }

QPushButton#primary {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 $PINK, stop:1 $CYAN);
    color: $BG; border: none; border-radius: 16px; padding: 14px 26px;
    font-size: 15px; font-weight: 800;
}
QPushButton#primary:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FF6E9F, stop:1 #6BFFF9);
}
QPushButton#ghost {
    background: transparent; border: 1px solid $BORDER; border-radius: 16px;
    padding: 13px 22px; font-weight: 700;
}
QPushButton#ghost:hover { border-color: $CYAN; }
QPushButton#link { background: transparent; border: none; color: $CYAN; font-weight: 700; text-align: left; padding: 4px 0; }

#pill { border: 1px solid $BORDER; border-radius: 12px; padding: 5px 12px; font-size: 12px; font-weight: 700; color: $MUTED; }
#pill[active="true"] { color: $GREEN; border: 1px solid rgba(61,255,162,90); background: rgba(61,255,162,18); }

#inprogress {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 $PINK, stop:1 $CYAN);
    color: $BG; border-radius: 16px; padding: 7px 18px; font-size: 14px; font-weight: 800;
}

QScrollArea { border: none; background: transparent; }
QScrollArea > QWidget > QWidget { background: transparent; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 4px; }
QScrollBar::handle:vertical { background: #2E2E42; border-radius: 3px; min-height: 40px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""

_TOKENS = {
    "FONT": _FONT, "MONO": _MONO, "BG": BG, "SIDEBAR": SIDEBAR, "SURFACE": SURFACE,
    "SURFACE_2": SURFACE_2, "BORDER": BORDER, "TEXT": TEXT, "MUTED": MUTED, "DIM": DIM,
    "PINK": PINK, "CYAN": CYAN, "GREEN": GREEN, "AMBER": AMBER, "RED": RED,
}


def repolish(widget: QWidget) -> None:
    """Применить стиль заново после смены динамического свойства (tone, hover, active)."""
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def apply_theme(app: QApplication) -> None:
    app.setStyle("Fusion")
    app.setStyleSheet(Template(_QSS).substitute(_TOKENS))