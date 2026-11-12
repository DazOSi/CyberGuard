import logging
from collections.abc import Sequence
from pathlib import Path

from .config import ScanConfig
from .hashing import sha256_file
from .heuristics import run_heuristics
from .models import Finding, ProviderReport, ScanResult, Verdict
from .providers import Provider, build_providers
from .yara_scan import YaraScanError, YaraScanner

log = logging.getLogger(__name__)

SUSPICIOUS_AT = 30
DANGEROUS_AT = 70

_RECOMMENDATIONS = {
    Verdict.DANGEROUS: (
        "Не открывайте и не запускайте этот файл. Удалите его. Если он пришёл по почте "
        "или в мессенджере — не пересылайте дальше и предупредите отправителя."
    ),
    Verdict.SUSPICIOUS: (
        "Лучше не открывать этот файл. Если вы его ждали — уточните у отправителя "
        "другим способом (например, позвонив), что он его действительно отправлял. "
        "Если не ждали — удалите."
    ),
    Verdict.SAFE: (
        "Явных угроз не найдено. Это не стопроцентная гарантия: "
        "скачивайте файлы только из надёжных источников."
    ),
}

_NO_ENGINES = (
    "Не подключён ни один антивирусный движок или база угроз, поэтому проверка по сигнатурам "
    "не выполнена. Установите ClamAV или включите Microsoft Defender."
)


class FileScanError(Exception):
    """Ошибка с понятным пользователю текстом (файл недоступен и т. п.)."""


class FileScanner:
    """Создавайте один экземпляр и переиспользуйте: правила YARA компилируются при создании."""

    def __init__(
        self,
        config: ScanConfig,
        *,
        providers: Sequence[Provider] | None = None,
        yara_scanner: YaraScanner | None = None,
    ) -> None:
        self._config = config
        self._providers = list(build_providers(config) if providers is None else providers)
        self._yara = yara_scanner or YaraScanner(config.rules_dir, timeout=config.yara_timeout)
        for error in self._yara.load_errors:
            log.warning("YARA: %s", error)

    def close(self) -> None:
        for provider in self._providers:
            closer = getattr(provider, "close", None)
            if callable(closer):
                closer()

    @staticmethod
    def _run_provider(provider: Provider, path: Path, sha256: str) -> ProviderReport:
        try:
            return provider.check(path, sha256)
        except Exception:  # провайдер не должен ронять всю проверку
            log.exception("Провайдер %s завершился с ошибкой", provider.name)
            return ProviderReport(provider.name, False, note="Одна из проверок не удалась.")

    def scan(self, path: str | Path) -> ScanResult:
        file_path = Path(path)
        if not file_path.is_file():
            raise FileScanError("Файл не найден (или это папка, а не файл).")
        try:
            size = file_path.stat().st_size
            sha256 = sha256_file(file_path, self._config.chunk_size)
            findings = run_heuristics(file_path, self._config.downloads_dirs)
        except PermissionError as exc:
            raise FileScanError("Нет доступа к файлу. Проверьте права или закройте программу, которая его использует.") from exc
        except OSError as exc:
            raise FileScanError("Не удалось прочитать файл.") from exc

        skipped: list[str] = []

        if not self._providers:
            skipped.append(_NO_ENGINES)
        for provider in self._providers:
            report = self._run_provider(provider, file_path, sha256)
            if report.available:
                findings += report.findings
            else:
                skipped.append(report.note)

        if not self._yara.available:
            skipped.append("Проверка по правилам не выполнена: набор правил не найден.")
        elif size > self._config.yara_max_bytes:
            skipped.append("Файл очень большой, проверка по правилам пропущена.")
        else:
            try:
                findings += self._yara.scan(file_path)
            except YaraScanError as exc:
                log.warning("YARA не завершилась: %s", exc)
                skipped.append("Проверка по правилам не завершилась.")

        return self._build_result(file_path, sha256, findings, skipped)

    @staticmethod
    def _build_result(path: Path, sha256: str, findings: list[Finding], skipped: list[str]) -> ScanResult:
        score = min(100, sum(f.points for f in findings))
        if score >= DANGEROUS_AT:
            verdict = Verdict.DANGEROUS
        elif score >= SUSPICIOUS_AT:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.SAFE

        ordered = sorted(findings, key=lambda f: f.points, reverse=True)
        reasons = [f.text for f in ordered]
        if not any(f.points > 0 for f in ordered):
            reasons.insert(0, "Явных признаков угрозы не найдено.")

        recommendation = _RECOMMENDATIONS[verdict]
        if verdict is Verdict.SAFE and skipped:
            recommendation += " Часть проверок не выполнена — повторите проверку позже."
        return ScanResult(
            path=path, sha256=sha256, verdict=verdict,
            reasons=tuple(reasons), recommendation=recommendation, score=score,
            complete=not skipped, skipped_checks=tuple(skipped),
            technical=tuple(f.technical for f in ordered if f.technical),
        )


def scan_file(path: str | Path, config: ScanConfig | None = None) -> ScanResult:
    scanner = FileScanner(config or ScanConfig.from_env())
    try:
        return scanner.scan(path)
    finally:
        scanner.close()