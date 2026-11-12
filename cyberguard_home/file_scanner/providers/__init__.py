import logging

from ..config import ScanConfig
from ..storage import Storage
from ..vt_client import VirusTotalClient
from .base import Provider
from .clamav import ClamAvProvider
from .clamav_runtime import find_runtime
from .defender import WindowsDefenderProvider, find_mpcmdrun
from .local_hashes import LocalHashListProvider
from .virustotal import VirusTotalProvider

log = logging.getLogger(__name__)
__all__ = ["Provider", "build_providers"]


def build_providers(config: ScanConfig) -> list[Provider]:
    providers: list[Provider] = []

    if config.hash_list_path is not None:
        if config.hash_list_path.is_file():
            providers.append(LocalHashListProvider(config.hash_list_path))
        else:
            log.warning("Файл базы хэшей не найден: %s", config.hash_list_path)

    if config.use_defender and (exe := find_mpcmdrun()):
        providers.append(WindowsDefenderProvider(exe, timeout=config.engine_timeout))

    if config.use_clamav and (runtime := find_runtime(config)):
        providers.append(ClamAvProvider(
            runtime.clamscan, database_dir=runtime.db_dir, timeout=config.engine_timeout))

    # VirusTotal: только при явно подтверждённой лицензии. Бесплатный ключ в коммерции запрещён.
    if config.online_lookup and config.vt_api_key:
        if config.vt_license == "none":
            log.warning("Ключ VirusTotal задан, но лицензия не подтверждена "
                        "(CYBERGUARD_VT_LICENSE). VirusTotal отключён.")
        else:
            client = VirusTotalClient(
                config.vt_api_key, Storage(config.db_path), timeout=config.http_timeout,
                per_minute=config.vt_per_minute, per_day=config.vt_per_day,
            )
            providers.append(VirusTotalProvider(client))

    return providers