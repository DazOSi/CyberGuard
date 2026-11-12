from pathlib import Path

import pytest

from cyberguard_home.file_scanner import ScanConfig

# Стандартный безвредный тестовый файл EICAR. Строка собрана из двух частей,
# чтобы антивирус не удалял сам исходник теста.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()
PROJECT_RULES = Path(__file__).resolve().parents[1] / "rules"
SHA_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


@pytest.fixture
def config(tmp_path: Path) -> ScanConfig:
    return ScanConfig(
        rules_dir=PROJECT_RULES,
        db_path=tmp_path / "cache.db",
        downloads_dirs=(tmp_path / "Downloads",),
        use_clamav=False,          # тесты не зависят от установленных антивирусов
        use_defender=False,
    )