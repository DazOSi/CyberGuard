from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class Verdict(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


class VtStatus(StrEnum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    NO_KEY = "no_key"
    BAD_KEY = "bad_key"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class VtReport:
    status: VtStatus
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0

    @property
    def total(self) -> int:
        return self.malicious + self.suspicious + self.harmless + self.undetected


@dataclass(frozen=True, slots=True)
class Finding:
    """Одна находка. text — для человека, technical — для раздела «Подробности»."""
    code: str
    text: str
    points: int = 0
    technical: str = ""


@dataclass(frozen=True, slots=True)
class ProviderReport:
    """Ответ одного источника проверки (движок, база хэшей, облачный сервис)."""
    provider: str
    available: bool                      # False — проверка не выполнена
    findings: tuple[Finding, ...] = ()
    note: str = ""                       # понятная причина, если available=False


@dataclass(frozen=True, slots=True)
class ScanResult:
    path: Path
    sha256: str
    verdict: Verdict
    reasons: tuple[str, ...]
    recommendation: str
    score: int
    complete: bool
    skipped_checks: tuple[str, ...] = ()
    technical: tuple[str, ...] = ()