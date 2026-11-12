from pathlib import Path

from PySide6.QtCore import QRectF, Qt, QTimer, Signal
from PySide6.QtGui import (
    QBrush, QColor, QDragEnterEvent, QDropEvent, QFontMetrics,
    QLinearGradient, QMouseEvent, QPainter, QPainterPath,
)
from PySide6.QtWidgets import (
    QFileDialog, QFrame, QHBoxLayout, QLabel, QPushButton, QSizePolicy,
    QStackedWidget, QVBoxLayout, QWidget,
)

from . import theme
from .presenter import ResultView


def make_label(name: str, text: str = "", *, wrap: bool = False, selectable: bool = False) -> QLabel:
    """Подпись, которая всегда показывает текст как есть (имена файлов не разбираются как HTML)."""
    label = QLabel(text)
    label.setObjectName(name)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(wrap)
    if selectable:
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


def elide(label: QLabel, text: str, width: int = 480) -> str:
    return QFontMetrics(label.font()).elidedText(text, Qt.TextElideMode.ElideMiddle, width)


def fit_wrapped(label: QLabel, width: int) -> None:
    """Задать ширину и точную высоту многострочной подписи, чтобы текст не обрезался."""
    label.setFixedWidth(width)
    label.ensurePolished()
    height = label.heightForWidth(width)
    if height > 0:
        label.setFixedHeight(height + 6)


class AdaptiveStack(QStackedWidget):
    """
    QStackedWidget, который подстраивается под текущую страницу, а не под самую высокую.
    Страницы с политикой Ignored не учитываются при расчёте размера.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.currentChanged.connect(self._sync)

    def addWidget(self, widget: QWidget) -> int:
        index = super().addWidget(widget)
        self._sync()
        return index

    def _sync(self, _index: int = 0) -> None:
        current = self.currentWidget()
        for i in range(self.count()):
            page = self.widget(i)
            policy = QSizePolicy.Policy.Preferred if page is current else QSizePolicy.Policy.Ignored
            page.setSizePolicy(policy, policy)
        self.updateGeometry()


class TextBox(QFrame):
    """
    Рамка с текстом. Отступы заданы у фрейма, а не у QLabel,
    поэтому многострочный текст считается верно и не обрезается.
    """

    def __init__(self, name: str, *, selectable: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName(name)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        self._label = make_label("boxtext", wrap=True, selectable=selectable)
        lay.addWidget(self._label)

    def set_text(self, text: str) -> None:
        self._label.setText(text)

    def text(self) -> str:
        return self._label.text()


class DropZone(QFrame):
    """Большая зона: перетащи файл или нажми, чтобы выбрать."""
    file_chosen = Signal(object)    # Path
    rejected = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("dropzone")
        self.setProperty("hover", False)
        self.setAcceptDrops(True)
        self.setMinimumHeight(300)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.setSpacing(10)
        for name, text in (("dropicon", "🛡️"), ("droptitle", "Перетащи файл сюда"), ("sub", "или нажми, чтобы выбрать")):
            label = make_label(name, text)
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            lay.addWidget(label)

    def handle_paths(self, paths: list[Path]) -> None:
        if not paths:
            self.rejected.emit("Не получилось открыть файл. Попробуй выбрать его кнопкой.")
            return
        first = paths[0]
        if first.is_dir():
            self.rejected.emit("Это папка. Перетащи сам файл.")
            return
        self.file_chosen.emit(first)

    def _set_hover(self, value: bool) -> None:
        self.setProperty("hover", value)
        theme.repolish(self)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._set_hover(True)
        else:
            event.ignore()

    def dragLeaveEvent(self, event) -> None:  # noqa: ANN001
        self._set_hover(False)
        event.accept()

    def dropEvent(self, event: QDropEvent) -> None:
        self._set_hover(False)
        paths = [Path(u.toLocalFile()) for u in event.mimeData().urls() if u.isLocalFile()]
        event.acceptProposedAction()
        self.handle_paths(paths)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            name, _ = QFileDialog.getOpenFileName(self, "Выбери файл для проверки")
            if name:
                self.handle_paths([Path(name)])
        super().mouseReleaseEvent(event)


class ShimmerBar(QWidget):
    """Тонкая полоска с бегущим неоновым градиентом."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(6)
        self._t = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(16)
        self._timer.timeout.connect(self._tick)

    def start(self) -> None:
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    def _tick(self) -> None:
        self._t = (self._t + 0.012) % 1.0
        self.update()

    def paintEvent(self, event) -> None:  # noqa: ANN001
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect())
        radius = rect.height() / 2
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(theme.SURFACE_2))
        painter.drawRoundedRect(rect, radius, radius)

        segment = rect.width() * 0.35
        x = -segment + self._t * (rect.width() + segment)
        gradient = QLinearGradient(x, 0, x + segment, 0)
        gradient.setColorAt(0.0, QColor(theme.PINK))
        gradient.setColorAt(1.0, QColor(theme.CYAN))
        clip = QPainterPath()
        clip.addRoundedRect(rect, radius, radius)
        painter.setClipPath(clip)
        painter.setBrush(QBrush(gradient))
        painter.drawRoundedRect(QRectF(x, 0, segment, rect.height()), radius, radius)
        painter.end()


class Pill(QLabel):
    def __init__(self, text: str, active: bool, tooltip: str = "", parent: QWidget | None = None) -> None:
        super().__init__(("● " if active else "○ ") + text, parent)
        self.setObjectName("pill")
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setProperty("active", active)
        self.setToolTip(tooltip)


class ResultCard(QFrame):
    """Карточка с вердиктом. Цвет рамки задаётся свойством tone."""
    again_clicked = Signal()
    reveal_clicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("resultcard")
        self.setProperty("tone", "safe")

        root = QVBoxLayout(self)
        root.setContentsMargins(34, 30, 34, 30)
        root.setSpacing(14)

        self._emoji = make_label("bigemoji")
        self._title = make_label("h1", wrap=True)
        self._subtitle = make_label("sub", wrap=True)
        self._file = make_label("small")
        self._reasons = make_label("reasons", wrap=True)
        self._reco = TextBox("callout")
        self._notice = TextBox("notice")
        self._details = TextBox("details", selectable=True)
        self._details.hide()

        self._toggle = QPushButton("Подробности")
        self._toggle.setObjectName("link")
        self._toggle.setCheckable(True)
        self._toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self._toggle.toggled.connect(self._on_toggle)

        again = QPushButton("Проверить ещё файл")
        again.setObjectName("primary")
        again.setCursor(Qt.CursorShape.PointingHandCursor)
        again.clicked.connect(self.again_clicked)
        reveal = QPushButton("Показать в папке")
        reveal.setObjectName("ghost")
        reveal.setCursor(Qt.CursorShape.PointingHandCursor)
        reveal.clicked.connect(self.reveal_clicked)
        buttons = QHBoxLayout()
        buttons.setSpacing(12)
        buttons.addWidget(again)
        buttons.addWidget(reveal)
        buttons.addStretch(1)

        for widget in (self._emoji, self._title, self._subtitle, self._file, self._reasons,
                       self._reco, self._notice, self._toggle, self._details):
            root.addWidget(widget)
        root.addSpacing(6)
        root.addLayout(buttons)

    def show_result(self, view: ResultView, path: Path) -> None:
        self.setProperty("tone", view.tone)
        theme.repolish(self)
        self._emoji.setText(view.emoji)
        self._title.setText(view.title)
        self._subtitle.setText(view.subtitle)
        self._file.setText(elide(self._file, path.name, 520))
        self._reasons.setText("\n".join(f"•  {reason}" for reason in view.reasons))
        self._reco.set_text(view.recommendation)
        self._notice.set_text("\n".join(view.notices))
        self._notice.setVisible(bool(view.notices))
        self._details.set_text(view.details)
        self._toggle.setChecked(False)
        self._details.setVisible(False)

    def _on_toggle(self, checked: bool) -> None:
        self._details.setVisible(checked)
        self._toggle.setText("Скрыть подробности" if checked else "Подробности")