import re
from pathlib import Path

from ..models import Finding, ProviderReport

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def load_hash_list(path: Path) -> dict[str, str]:
    """Формат: одна строка — один SHA-256, после пробела необязательное название. # — комментарий."""
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        digest = parts[0].lower()
        if _HASH_RE.fullmatch(digest):
            result[digest] = parts[1].strip() if len(parts) > 1 else ""
    return result


class LocalHashListProvider:
    """Офлайн-проверка по вашей собственной базе хэшей. Лицензия базы — на вашей совести."""
    name = "local_hashes"

    def __init__(self, path: Path) -> None:
        self._db = load_hash_list(path)

    def check(self, path: Path, sha256: str) -> ProviderReport:
        label = self._db.get(sha256.lower())
        if label is None:
            return ProviderReport(self.name, True)
        return ProviderReport(self.name, True, (Finding(
            "local_hash_match",
            "Этот файл есть в базе известных вредоносных программ.",
            100,
            f"hashlist: {label or sha256}",
        ),))