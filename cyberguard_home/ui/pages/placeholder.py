from PySide6.QtCore import Qt
from PySide6.QtWidgets import QVBoxLayout, QWidget

from ..widgets import fit_wrapped, make_label


class PlaceholderPage(QWidget):
    """Заглушка раздела. Заменяется настоящей страницей через Feature.factory."""

    def __init__(self, title: str, icon: str, tagline: str) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.setSpacing(14)

        center = Qt.AlignmentFlag.AlignCenter
        emoji = make_label("bigemoji", icon)
        emoji.setAlignment(center)
        heading = make_label("h1", title)
        heading.setAlignment(center)
        chip = make_label("inprogress", "in progress")
        chip.setAlignment(center)
        text = make_label("sub", tagline, wrap=True)
        text.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
        fit_wrapped(text, 420)          # точная высота: нижняя строка больше не обрезается

        lay.addWidget(emoji)
        lay.addWidget(heading)
        lay.addWidget(chip, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addWidget(text, 0, Qt.AlignmentFlag.AlignHCenter)