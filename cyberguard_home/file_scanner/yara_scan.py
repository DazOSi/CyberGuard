
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:
    import yara
except ImportError:
    yara = None

if TYPE_CHECKING:
    import yara as yara_types

from .models import Finding

log = logging.getLogger(__name__)

# Внешние переменные для открытых наборов YARA-правил.
_EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
    "owner": "",
}

_SUFFIXES = {".yar", ".yara"}

_FRIENDLY = {
    "CG_EICAR_Test_File": (
        "Это стандартный тестовый файл EICAR. Он безвреден, но защитные "
        "программы договорились считать его «вирусом» — так проверяют, "
        "что защита работает."
    ),
}

_GENERIC = (
    "Содержимое файла совпало с признаками известной вредоносной программы."
)

_MAX_REPORTED = 5


class YaraScanError(RuntimeError):
    """Проверка по правилам не завершилась (таймаут или ошибка движка)."""



class YaraScanner:

    def __init__(self, rules_dir: Path, *, timeout: int = 30) -> None:
        self._timeout = timeout
        self.load_errors: list[str] = []
        self._rules = self._compile(rules_dir)

    @property
    def available(self) -> bool:
        return self._rules is not None

    def _compile(self, rules_dir: Path) -> Any | None:
        if yara is None:
            self.load_errors.append(
                "Библиотека yara-python не установлена"
            )
            return None

        if not rules_dir.is_dir():
            self.load_errors.append(
                f"Папка с правилами не найдена: {rules_dir}"
            )
            return None

        sources = sorted(
            p for p in rules_dir.rglob("*")
            if p.is_file() and p.suffix.lower() in _SUFFIXES
        )

        good: dict[str, str] = {}

        for index, source in enumerate(sources):
            try:
                yara.compile(
                    filepath=str(source),
                    externals=_EXTERNALS,
                )
            except yara.Error as exc:
                log.warning(
                    "Правило пропущено: %s (%s)",
                    source.name,
                    exc,
                )
                self.load_errors.append(f"{source.name}: {exc}")
                continue

            good[f"ns{index}"] = str(source)

        if not good:
            return None

        try:
            return yara.compile(
                filepaths=good,
                externals=_EXTERNALS,
            )
        except yara.Error as exc:
            self.load_errors.append(
                f"Общая компиляция не удалась: {exc}"
            )
            return None

    def scan(self, path: Path) -> list[Finding]:
        if self._rules is None:
            return []

        if not path.is_file():
            raise YaraScanError(
                f"Файл не найден или недоступен: {path}"
            )

        try:
            data = path.read_bytes()
        except OSError as exc:
            raise YaraScanError(
                f"Не удалось прочитать файл: {exc}"
            ) from exc

        return self.scan_data(data, path=path)

    def scan_data(
        self,
        data: bytes,
        *,
        path: Path | None = None,
        filename: str = "",
    ) -> list[Finding]:

        if self._rules is None:
            return []

        if path is not None:
            filename = path.name
            filepath = str(path)
            extension = path.suffix
        else:
            filepath = filename
            extension = Path(filename).suffix

        externals = {
            "filename": filename,
            "filepath": filepath,
            "extension": extension,
            "filetype": extension.lstrip(".").upper(),
            "owner": "",
        }

        try:
            matches = self._rules.match(
                data=data,
                externals=externals,
                timeout=self._timeout,
            )
        except yara.TimeoutError as exc:
            raise YaraScanError("таймаут") from exc
        except yara.Error as exc:
            raise YaraScanError(str(exc)) from exc

        findings: list[Finding] = []

        for match in matches[:_MAX_REPORTED]:
            raw = match.meta.get("score")
            points = (
                max(1, min(100, raw))
                if isinstance(raw, int)
                else 70
            )

            description = match.meta.get("description", "")
            author = match.meta.get("author", "")
            license_ = match.meta.get("license", "")

            technical = f"YARA: {match.rule}"

            if description:
                technical += f" — {description}"

            if author or license_:
                technical += (
                    f" (автор: {author or '—'}; "
                    f"лицензия: {license_ or '—'})"
                )

            findings.append(
                Finding(
                    f"yara:{match.rule}",
                    _FRIENDLY.get(match.rule, _GENERIC),
                    points,
                    technical,
                )
            )

        return findings
