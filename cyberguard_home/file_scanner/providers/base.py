from pathlib import Path
from typing import Protocol

from ..models import ProviderReport


class Provider(Protocol):
    """Источник проверки. check() не должен бросать исключения наружу."""
    name: str

    def check(self, path: Path, sha256: str) -> ProviderReport: ...