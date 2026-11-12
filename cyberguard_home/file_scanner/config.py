import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

VT_LICENSES = frozenset({"none", "noncommercial", "premium"})


def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw not in {"0", "false", "no", "off"}


def _int_or_none(name: str) -> int | None:
    try:
        value = int(os.getenv(name, "").strip())
    except ValueError:
        return None
    return value if value > 0 else None


def _path_or_none(name: str) -> Path | None:
    raw = os.getenv(name, "").strip()
    return Path(raw) if raw else None


@dataclass(frozen=True, slots=True)
class ScanConfig:
    rules_dir: Path
    db_path: Path
    downloads_dirs: tuple[Path, ...]
    # Локальные источники
    hash_list_path: Path | None = None
    use_clamav: bool = True              # работает, только если clamscan найден
    clamav_path: str | None = None       # явный путь к clamscan
    clamav_bundle_dir: Path | None = None  # папка со встроенным ClamAV (по умолчанию vendor/clamav)
    clamav_db_dir: Path | None = None    # где хранить базу сигнатур встроенного ClamAV
    clamav_update_interval: float = 6 * 3600
    use_defender: bool = True            # только Windows
    engine_timeout: float = 120.0
    # VirusTotal: по умолчанию выключен. Нужна подтверждённая лицензия.
    vt_api_key: str | None = None
    vt_license: str = "none"             # none | noncommercial | premium
    online_lookup: bool = True           # False — вообще без сети
    vt_per_minute: int | None = 4
    vt_per_day: int | None = 500
    # Прочее
    chunk_size: int = 1024 * 1024
    http_timeout: float = 10.0
    yara_timeout: int = 30
    yara_max_bytes: int = 200 * 1024 * 1024

    @classmethod
    def from_env(cls) -> "ScanConfig":
        load_dotenv()
        home = Path.home()
        root = Path(__file__).resolve().parents[2]
        rules_dir = Path(os.getenv("CYBERGUARD_RULES_DIR", root / "rules"))
        hash_list_path = Path(
        os.getenv("CYBERGUARD_HASH_LIST", root / "hashes" / "blocklist.txt")
        ).expanduser()

        vt_license = os.getenv("CYBERGUARD_VT_LICENSE", "none").strip().lower()
        if vt_license not in VT_LICENSES:
            vt_license = "none"
        if vt_license == "premium":      # квоты по вашему договору
            per_minute, per_day = _int_or_none("VT_PER_MINUTE"), _int_or_none("VT_PER_DAY")
        else:                            # квоты бесплатного ключа
            per_minute, per_day = 4, 500

        return cls(
            rules_dir=rules_dir,
            db_path=Path(os.getenv("CYBERGUARD_DB", home / ".cyberguard" / "cache.db")),
            downloads_dirs=(home / "Downloads", home / "Загрузки"),
            hash_list_path=hash_list_path,
            use_clamav=_flag("CYBERGUARD_USE_CLAMAV", True),
            clamav_path=os.getenv("CLAMSCAN_PATH") or None,
            clamav_bundle_dir=_path_or_none("CYBERGUARD_CLAMAV_DIR"),
            clamav_db_dir=_path_or_none("CYBERGUARD_CLAMAV_DB"),
            clamav_update_interval=6 * 3600,
            use_defender=_flag("CYBERGUARD_USE_DEFENDER", True),
            engine_timeout=120.0,
            vt_api_key=os.getenv("VT_API_KEY") or None,
            vt_license=vt_license,
            online_lookup=_flag("CYBERGUARD_ONLINE_LOOKUP", True),
            vt_per_minute=per_minute,
            vt_per_day=per_day,
        )