import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")   # без дисплея, для CI

import pytest
from PySide6.QtWidgets import QApplication, QLabel, QPushButton

from cyberguard_home.file_scanner import ScanConfig
from cyberguard_home.ui.context import AppContext
from cyberguard_home.ui.features import Feature, default_features
from cyberguard_home.ui.main_window import MainWindow
from cyberguard_home.ui.pages.scan_file import ScanFilePage
from cyberguard_home.ui.services import ScannerService
from cyberguard_home.ui.pages.placeholder import PlaceholderPage
from cyberguard_home.ui.widgets import AdaptiveStack, DropZone, TextBox
from tests.conftest import EICAR


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    return QApplication.instance() or QApplication([])


@pytest.fixture
def ctx(qapp: QApplication, config: ScanConfig):
    service = ScannerService(config)
    yield AppContext(config, service)
    service.shutdown()


def wait_until(qapp: QApplication, predicate, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        qapp.processEvents()
        if predicate():
            return True
        time.sleep(0.02)
    return False


def label_texts(widget) -> list[str]:
    return [label.text() for label in widget.findChildren(QLabel)]


def test_registry_ids_are_unique() -> None:
    ids = [f.id for f in default_features()]
    assert len(ids) == len(set(ids))


def test_window_has_nav_button_for_every_feature(qapp: QApplication, ctx: AppContext) -> None:
    features = default_features()
    window = MainWindow(ctx, features)
    buttons = [b for b in window.findChildren(QPushButton) if b.objectName() == "nav"]
    assert len(buttons) == len(features)


def test_unfinished_sections_say_in_progress(qapp: QApplication, ctx: AppContext) -> None:
    stubs = [f for f in default_features() if not f.ready]
    assert stubs
    for feature in stubs:
        assert "in progress" in label_texts(feature.build(ctx))


def test_factory_replaces_stub(qapp: QApplication, ctx: AppContext) -> None:
    feature = Feature("x", "X", "🧪", "text", factory=lambda c: QLabel("real page"))
    assert feature.ready and feature.build(ctx).text() == "real page"


def test_directory_drop_is_rejected(qapp: QApplication, tmp_path) -> None:
    zone = DropZone()
    messages: list[str] = []
    zone.rejected.connect(messages.append)
    zone.handle_paths([tmp_path])
    assert messages and "папка" in messages[0]


def test_scan_flow_shows_dangerous_card(qapp: QApplication, ctx: AppContext, tmp_path) -> None:
    f = tmp_path / "eicar.txt"
    f.write_bytes(EICAR)
    page = ScanFilePage(ctx)
    page.start_scan(f)
    assert wait_until(qapp, lambda: "Опасный файл" in label_texts(page))


def test_missing_file_shows_friendly_banner(qapp: QApplication, ctx: AppContext, tmp_path) -> None:
    page = ScanFilePage(ctx)
    page.start_scan(tmp_path / "нет-такого.txt")
    banner = page.findChild(TextBox, "banner")
    assert wait_until(qapp, lambda: not banner.isHidden())
    assert "Файл не найден" in banner.text()

def test_placeholder_tagline_has_room_for_all_lines(qapp: QApplication) -> None:
    page = PlaceholderPage("Проверка ссылок", "🔗", "Вставь ссылку из сообщения — скажу, не мошенники ли это.")
    label = next(l for l in page.findChildren(QLabel) if l.objectName() == "sub")
    assert label.minimumHeight() >= label.heightForWidth(420)

def test_stack_is_sized_by_current_page(qapp: QApplication) -> None:
    stack = AdaptiveStack()
    small, tall = QLabel("x"), QLabel("x\n" * 40)
    stack.addWidget(small)
    stack.addWidget(tall)
    stack.setCurrentWidget(small)
    assert stack.sizeHint().height() < tall.sizeHint().height()    