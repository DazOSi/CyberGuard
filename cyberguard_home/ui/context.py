from dataclasses import dataclass

from ..file_scanner import ScanConfig
from .services import ScannerService


@dataclass(frozen=True, slots=True)
class AppContext:
    """Всё, что нужно страницам: настройки и сервис. Новые страницы получают это же."""
    config: ScanConfig
    service: ScannerService