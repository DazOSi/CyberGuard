import itertools
import logging
import threading
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, Signal, Slot

from ..file_scanner import FileScanError, FileScanner, ScanConfig
from ..file_scanner.providers.clamav_runtime import database_ready, find_runtime, update_database
from .presenter import EnginePill, build_engine_pills

log = logging.getLogger(__name__)

GENERIC_ERROR = "Что-то пошло не так. Попробуй ещё раз."
Callback = Callable[[Any], None]


class ScannerService(QObject):
    """
    Фоновые задачи для интерфейса. Тяжёлую работу делают потоки-демоны,
    результат возвращается в главный поток через сигнал. Окно не подвисает,
    а при выходе из приложения нет ожидания долгой загрузки базы.
    """
    engines_ready = Signal(object)          # tuple[EnginePill, ...]
    database_message = Signal(str)
    _done = Signal(int, object, object)     # token, value, error_text

    def __init__(
        self,
        config: ScanConfig,
        *,
        scanner_factory: Callable[[ScanConfig], FileScanner] = FileScanner,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._config = config
        self._factory = scanner_factory
        self._scanner: FileScanner | None = None
        self._build_lock = threading.Lock()
        self._scan_lock = threading.Lock()      # проверки идут по одной
        self._callbacks: dict[int, tuple[Callback | None, Callback | None]] = {}
        self._ids = itertools.count(1)
        self._closing = False
        self.engine_pills: tuple[EnginePill, ...] | None = None
        self.last_database_message: str = ""
        self._done.connect(self._dispatch)

    # ---------- публичный интерфейс ----------
    def scan(self, path: Path, on_result: Callback, on_error: Callback) -> None:
        self._run(lambda: self._get_scanner().scan(path), on_result, on_error, self._scan_lock)

    def start_background(self) -> None:
        self._run(self._warm_up, self._on_warm, None)
        if not self._config.use_clamav:
            return
        runtime = find_runtime(self._config)
        if runtime is None or not runtime.manages_database:
            return
        if runtime.db_dir is not None and not database_ready(runtime.db_dir):
            self._set_database_message("Загружаю базу защиты — это нужно только один раз.")
        self._run(self._update_clamav, self._on_update, None)

    def shutdown(self) -> None:
        self._closing = True
        if self._scanner is not None:
            self._scanner.close()

    # ---------- внутреннее ----------
    def _get_scanner(self) -> FileScanner:
        with self._build_lock:
            if self._scanner is None:
                self._scanner = self._factory(self._config)
            return self._scanner

    def _warm_up(self) -> tuple[EnginePill, ...]:
        scanner = self._get_scanner()
        return build_engine_pills(scanner.provider_names, scanner.rules_available)

    def _on_warm(self, pills: tuple[EnginePill, ...]) -> None:
        self.engine_pills = pills
        self.engines_ready.emit(pills)

    def _update_clamav(self) -> str | None:
        runtime = find_runtime(self._config)
        if runtime is None or not runtime.manages_database:
            return None
        return update_database(runtime, interval=self._config.clamav_update_interval).message

    def _on_update(self, message: str | None) -> None:
        if message:
            self._set_database_message(message)

    def _set_database_message(self, message: str) -> None:
        self.last_database_message = message
        self.database_message.emit(message)

    def _run(
        self,
        fn: Callable[[], object],
        on_result: Callback | None,
        on_error: Callback | None,
        lock: AbstractContextManager[Any] | None = None,
    ) -> None:
        token = next(self._ids)
        self._callbacks[token] = (on_result, on_error)

        def job() -> None:
            value: object = None
            error: str | None = None
            try:
                with lock if lock is not None else nullcontext():
                    value = fn()
            except FileScanError as exc:
                error = str(exc)
            except Exception:
                log.exception("Фоновая задача завершилась с ошибкой")
                error = GENERIC_ERROR
            if not self._closing:
                self._done.emit(token, value, error)

        threading.Thread(target=job, daemon=True, name=f"cg-task-{token}").start()

    @Slot(int, object, object)
    def _dispatch(self, token: int, value: object, error: object) -> None:
        on_result, on_error = self._callbacks.pop(token, (None, None))
        if error is not None:
            if on_error is not None:
                on_error(error)
        elif on_result is not None:
            on_result(value)