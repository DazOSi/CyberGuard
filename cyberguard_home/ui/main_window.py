from collections.abc import Sequence

from .widgets import AdaptiveStack

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup, QFrame, QHBoxLayout, QLabel, QMainWindow, QPushButton,
    QStackedWidget, QVBoxLayout, QWidget,
)

from . import theme
from .context import AppContext
from .features import Feature


class MainWindow(QMainWindow):
    def __init__(self, ctx: AppContext, features: Sequence[Feature]) -> None:
        super().__init__()
        self.setWindowTitle("CyberGuard Home")
        self.resize(1080, 720)
        self.setMinimumSize(900, 640)

        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._stack = AdaptiveStack()
        layout.addWidget(self._build_sidebar(features))
        layout.addWidget(self._stack, 1)

        for feature in features:
            self._stack.addWidget(feature.build(ctx))
        self._group.idClicked.connect(self._stack.setCurrentIndex)
        if (first := self._group.button(0)) is not None:
            first.setChecked(True)

    def _build_sidebar(self, features: Sequence[Feature]) -> QFrame:
        bar = QFrame()
        bar.setObjectName("sidebar")
        bar.setFixedWidth(250)
        lay = QVBoxLayout(bar)
        lay.setContentsMargins(18, 26, 18, 18)
        lay.setSpacing(6)

        logo = QLabel(f'<span style="color:{theme.PINK}">Cyber</span>'
                      f'<span style="color:{theme.CYAN}">Guard</span>')
        logo.setObjectName("logo")
        logo.setTextFormat(Qt.TextFormat.RichText)
        tagline = QLabel("защита для своих")
        tagline.setObjectName("tagline")
        lay.addWidget(logo)
        lay.addWidget(tagline)
        lay.addSpacing(22)

        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        for index, feature in enumerate(features):
            button = QPushButton(f"{feature.icon}   {feature.title}")
            button.setObjectName("nav")
            button.setCheckable(True)
            button.setProperty("ready", feature.ready)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            self._group.addButton(button, index)
            lay.addWidget(button)

        lay.addStretch(1)
        version = QLabel("v0.1 · beta") #версия приложения 
        version.setObjectName("version")
        lay.addWidget(version) 
        return bar