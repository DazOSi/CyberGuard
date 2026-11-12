from pathlib import Path

from cyberguard_home.file_scanner import ScanResult, Verdict
from cyberguard_home.ui.presenter import build_engine_pills, present


def make_result(verdict: Verdict, *, complete: bool = True, skipped=(), technical=(), score: int = 0) -> ScanResult:
    return ScanResult(
        path=Path("/tmp/счёт.pdf.exe"), sha256="ab" * 32, verdict=verdict,
        reasons=("Причина один",), recommendation="Не открывай", score=score,
        complete=complete, skipped_checks=tuple(skipped), technical=tuple(technical),
    )


def test_safe_and_complete() -> None:
    view = present(make_result(Verdict.SAFE))
    assert view.tone == "safe" and view.title == "Всё чисто" and not view.notices


def test_safe_but_incomplete_is_honest() -> None:
    view = present(make_result(Verdict.SAFE, complete=False, skipped=("Нет связи",)))
    assert view.emoji == "🤔" and "Похоже" in view.title and view.notices == ("Нет связи",)


def test_dangerous_card_and_details() -> None:
    view = present(make_result(Verdict.DANGEROUS, score=100, technical=("ClamAV: Eicar",)))
    assert view.tone == "dangerous" and view.title == "Опасный файл"
    assert "ab" * 32 in view.details and "счёт.pdf.exe" in view.details
    assert "ClamAV: Eicar" in view.details and "100 из 100" in view.details


def test_suspicious_tone() -> None:
    assert present(make_result(Verdict.SUSPICIOUS)).tone == "suspicious"


def test_engine_pills() -> None:
    pills = {p.label: p.active for p in build_engine_pills(("clamav",), True)}
    assert pills == {"ClamAV": True, "Защитник Windows": False, "Правила": True}
    extra = {p.label for p in build_engine_pills(("virustotal", "local_hashes"), False)}
    assert {"Онлайн-база", "Своя база"} <= extra