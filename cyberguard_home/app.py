import logging
import sys

from PySide6.QtWidgets import QApplication

from .file_scanner import ScanConfig
from .ui.context import AppContext
from .ui.features import default_features
from .ui.main_window import MainWindow
from .ui.services import ScannerService
from .ui.theme import apply_theme


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app = QApplication(sys.argv if argv is None else argv)
    app.setApplicationName("CyberGuard Home")
    apply_theme(app)

    config = ScanConfig.from_env()
    service = ScannerService(config)
    ctx = AppContext(config, service)

    window = MainWindow(ctx, default_features())
    app.aboutToQuit.connect(service.shutdown)
    window.show()
    service.start_background()      # прогрев движков и обновление базы — не блокирует окно
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())