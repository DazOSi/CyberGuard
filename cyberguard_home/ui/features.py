from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtWidgets import QWidget

from .context import AppContext
from .pages.placeholder import PlaceholderPage
from .pages.scan_file import ScanFilePage

PageFactory = Callable[[AppContext], QWidget]


@dataclass(frozen=True, slots=True)
class Feature:
    id: str
    title: str
    icon: str
    tagline: str                          # текст под «in progress»
    factory: PageFactory | None = None    # None → показываем заглушку

    @property
    def ready(self) -> bool:
        return self.factory is not None

    def build(self, ctx: AppContext) -> QWidget:
        if self.factory is not None:
            return self.factory(ctx)
        return PlaceholderPage(self.title, self.icon, self.tagline)


def default_features() -> list[Feature]:
    return [
        Feature("scan_file", "Проверка файла", "🛡️",
                "Перетащи файл — скажу, можно ли ему доверять.", factory=ScanFilePage),
        Feature("scan_link", "Проверка ссылок", "🔗",
                "Вставь ссылку из сообщения — скажу, не мошенники ли это."),
        Feature("realtime", "Защита в фоне", "👀",
                "Следим за папкой «Загрузки» и проверяем новые файлы сами."),
        Feature("history", "История", "🕘",
                "Все проверки в одном месте — чтобы ничего не потерять."),
        Feature("settings", "Настройки", "⚙️",
                "Движки защиты, обновления и приватность."),
    ]