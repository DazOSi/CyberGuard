from collections.abc import Sequence
from dataclasses import dataclass

from ..file_scanner import ScanResult, Verdict


@dataclass(frozen=True, slots=True)
class ResultView:
    tone: str                       # safe | suspicious | dangerous
    emoji: str
    title: str
    subtitle: str
    reasons: tuple[str, ...]
    recommendation: str
    notices: tuple[str, ...]        # что не удалось проверить
    details: str                    # текст для раскрывающегося блока


@dataclass(frozen=True, slots=True)
class EnginePill:
    label: str
    active: bool
    tooltip: str


_TONES = {
    Verdict.SAFE: ("safe", "✅", "Всё чисто", "Явных угроз не нашли"),
    Verdict.SUSPICIOUS: ("suspicious", "⚠️", "Лучше не открывать", "Файл выглядит подозрительно"),
    Verdict.DANGEROUS: ("dangerous", "🚨", "Опасный файл", "Не открывай и не запускай его"),
}


def present(result: ScanResult) -> ResultView:
    tone, emoji, title, subtitle = _TONES[result.verdict]
    if result.verdict is Verdict.SAFE and not result.complete:
        emoji, title, subtitle = "🤔", "Похоже, всё чисто", "Но часть проверок не удалось выполнить"

    lines = [
        f"Файл: {result.path.name}",
        f"Папка: {result.path.parent}",
        f"Цифровой отпечаток (SHA-256): {result.sha256}",
        f"Уровень риска: {result.score} из 100",
    ]
    if result.technical:
        lines += ["", "Что именно нашли:", *(f"  - {t}" for t in result.technical)]
    if result.skipped_checks:
        lines += ["", "Что не удалось проверить:", *(f"  - {s}" for s in result.skipped_checks)]

    return ResultView(
        tone=tone, emoji=emoji, title=title, subtitle=subtitle,
        reasons=result.reasons, recommendation=result.recommendation,
        notices=result.skipped_checks, details="\n".join(lines),
    )


def build_engine_pills(provider_names: Sequence[str], rules_available: bool) -> tuple[EnginePill, ...]:
    names = set(provider_names)
    pills = [
        EnginePill("ClamAV", "clamav" in names,
                   "Антивирусный движок ClamAV подключён" if "clamav" in names
                   else "ClamAV не подключён"),
        EnginePill("Защитник Windows", "defender" in names,
                   "Встроенная защита Windows подключена" if "defender" in names
                   else "Защитник Windows недоступен на этом компьютере"),
        EnginePill("Правила", rules_available,
                   "Набор правил для поиска вредоносных программ загружен" if rules_available
                   else "Набор правил не найден"),
    ]
    if "virustotal" in names:
        pills.append(EnginePill("Онлайн-база", True, "Отправляется только цифровой отпечаток файла, сам файл — нет"))
    if "local_hashes" in names:
        pills.append(EnginePill("Своя база", True, "Подключена локальная база известных угроз"))
    return tuple(pills)