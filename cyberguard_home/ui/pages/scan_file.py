from pathlib import Path

from PySide6.QtCore import QUrl, Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QFrame, QHBoxLayout, QScrollArea, QVBoxLayout, QWidget

from ...file_scanner import ScanResult
from ..context import AppContext
from ..presenter import EnginePill, present
from ..widgets import AdaptiveStack, DropZone, Pill, ResultCard, ShimmerBar, TextBox, elide, make_label


class ScanFilePage(QWidget):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self._ctx = ctx
        self._path: Path | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)

        lay = QVBoxLayout(body)
        lay.setContentsMargins(40, 36, 40, 28)
        lay.setSpacing(18)
        lay.addWidget(make_label("h1", "Проверка файла"))
        lay.addWidget(make_label("sub", "Перетащи файл — скажу, можно ли ему доверять", wrap=True))

        self._banner = TextBox("banner")
        self._banner.hide()
        lay.addWidget(self._banner)

        self._zone = DropZone()
        self._busy = self._build_busy_view()
        self._card = ResultCard()
        self._stack = AdaptiveStack()           # размер по текущей странице, а не по самой высокой
        for view in (self._zone, self._busy, self._card):
            self._stack.addWidget(view)
        lay.addWidget(self._stack, 1)
        lay.addLayout(self._build_footer())

        self._zone.file_chosen.connect(self.start_scan)
        self._zone.rejected.connect(self._show_banner)
        self._card.again_clicked.connect(self._reset)
        self._card.reveal_clicked.connect(self._reveal)

        service = ctx.service
        service.engines_ready.connect(self._set_engines)
        service.database_message.connect(self._set_database_message)
        self._set_engines(service.engine_pills or (EnginePill("Запускаю защиту…", False, ""),))
        if service.last_database_message:
            self._set_database_message(service.last_database_message)

    # ---------- построение ----------
    def _build_busy_view(self) -> QWidget:
        view = QFrame()
        view.setObjectName("busy")
        view.setMinimumHeight(300)
        lay = QVBoxLayout(view)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.setSpacing(14)
        center = Qt.AlignmentFlag.AlignCenter

        emoji = make_label("bigemoji", "🔍")
        emoji.setAlignment(center)
        title = make_label("h2", "Проверяю файл…")
        title.setAlignment(center)
        self._busy_name = make_label("small")
        self._busy_name.setAlignment(center)
        self._bar = ShimmerBar()
        self._bar.setFixedWidth(360)
        hint = make_label("small", "Обычно это занимает от нескольких секунд до минуты")
        hint.setAlignment(center)

        for widget in (emoji, title, self._busy_name):
            lay.addWidget(widget)
        lay.addWidget(self._bar, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addWidget(hint)
        return view

    def _build_footer(self) -> QVBoxLayout:
        footer = QVBoxLayout()
        footer.setSpacing(10)
        footer.addWidget(make_label("small", "🔒 Файл остаётся на твоём компьютере"))

        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(make_label("small", "Защита:"))
        self._pills_box = QWidget()
        self._pills_layout = QHBoxLayout(self._pills_box)
        self._pills_layout.setContentsMargins(0, 0, 0, 0)
        self._pills_layout.setSpacing(8)
        row.addWidget(self._pills_box)
        row.addStretch(1)
        footer.addLayout(row)

        self._db_status = make_label("small", wrap=True)
        self._db_status.hide()
        footer.addWidget(self._db_status)
        return footer

    # ---------- действия ----------
    def start_scan(self, path: Path) -> None:
        self._path = path
        self._banner.hide()
        self._busy_name.setText(elide(self._busy_name, path.name, 420))
        self._stack.setCurrentWidget(self._busy)
        self._bar.start()
        self._ctx.service.scan(path, self._on_result, self._on_error)

    def _on_result(self, result: ScanResult) -> None:
        self._bar.stop()
        self._card.show_result(present(result), result.path)
        self._stack.setCurrentWidget(self._card)

    def _on_error(self, message: str) -> None:
        self._bar.stop()
        self._show_banner(message)
        self._stack.setCurrentWidget(self._zone)

    def _show_banner(self, message: str) -> None:
        self._banner.set_text(message)
        self._banner.show()

    def _reset(self) -> None:
        self._banner.hide()
        self._stack.setCurrentWidget(self._zone)

    def _reveal(self) -> None:
        if self._path is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._path.parent)))

    def _set_engines(self, pills: tuple[EnginePill, ...]) -> None:
        while (item := self._pills_layout.takeAt(0)) is not None:
            if (widget := item.widget()) is not None:
                widget.deleteLater()
        for pill in pills:
            self._pills_layout.addWidget(Pill(pill.label, pill.active, pill.tooltip))

    def _set_database_message(self, message: str) -> None:
        self._db_status.setText(f"🛰 {message}")
        self._db_status.show()