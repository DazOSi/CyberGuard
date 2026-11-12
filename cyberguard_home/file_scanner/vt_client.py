import logging
import re
import sqlite3

import httpx

from .models import VtReport, VtStatus
from .storage import Storage

log = logging.getLogger(__name__)
_BASE = "https://www.virustotal.com/api/v3"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class VirusTotalClient:
    """Репутация файла по хэшу. Содержимое файла НИКОГДА не отправляется."""

    def __init__(
        self,
        api_key: str | None,
        storage: Storage,
        *,
        http: httpx.Client | None = None,
        timeout: float = 10.0,
        per_minute: int | None = 4,
        per_day: int | None = 500,
        ttl_found: float = 24 * 3600,
        ttl_missing: float = 3600,
    ) -> None:
        self._api_key = api_key
        self._storage = storage
        self._http = http or httpx.Client(timeout=httpx.Timeout(timeout))
        self._per_minute: int | None = per_minute
        self._per_day: int | None = per_day
        self._ttl_found = ttl_found
        self._ttl_missing = ttl_missing

    def close(self) -> None:
        self._http.close()

    def lookup(self, sha256: str) -> VtReport:
        if not self._api_key:
            return VtReport(VtStatus.NO_KEY)
        if not _SHA256_RE.fullmatch(sha256):
            return VtReport(VtStatus.ERROR)
        try:
            cached = self._storage.get_cached(sha256)
            if cached is not None:
                return cached
            if not self._storage.try_acquire(self._per_minute, self._per_day):
                return VtReport(VtStatus.RATE_LIMITED)
        except sqlite3.Error:
            log.warning("Локальный кэш недоступен", exc_info=True)
            return VtReport(VtStatus.ERROR)

        report = self._request(sha256)
        if report.status in (VtStatus.FOUND, VtStatus.NOT_FOUND):
            ttl = self._ttl_found if report.status is VtStatus.FOUND else self._ttl_missing
            try:
                self._storage.put_cached(sha256, report, ttl)
            except sqlite3.Error:
                log.warning("Не удалось записать кэш", exc_info=True)
        return report

    def _request(self, sha256: str) -> VtReport:
        try:
            resp = self._http.get(
                f"{_BASE}/files/{sha256}",
                headers={"x-apikey": self._api_key or "", "accept": "application/json"},
            )
        except httpx.TimeoutException:
            log.warning("VirusTotal: таймаут")
            return VtReport(VtStatus.ERROR)
        except httpx.HTTPError as exc:
            log.warning("VirusTotal: сетевая ошибка (%s)", type(exc).__name__)
            return VtReport(VtStatus.ERROR)

        code = resp.status_code
        if code == 404:
            return VtReport(VtStatus.NOT_FOUND)
        if code == 429:
            return VtReport(VtStatus.RATE_LIMITED)
        if code in (401, 403):
            return VtReport(VtStatus.BAD_KEY)
        if code != 200:
            log.warning("VirusTotal: неожиданный статус %s", code)
            return VtReport(VtStatus.ERROR)
        try:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            return VtReport(
                VtStatus.FOUND,
                malicious=int(stats.get("malicious", 0)),
                suspicious=int(stats.get("suspicious", 0)),
                harmless=int(stats.get("harmless", 0)),
                undetected=int(stats.get("undetected", 0)),
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            log.warning("VirusTotal: неожиданный формат ответа")
            return VtReport(VtStatus.ERROR)