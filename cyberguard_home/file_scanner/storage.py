import sqlite3
import time
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

from .models import VtReport, VtStatus

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vt_cache(
    sha256 TEXT PRIMARY KEY, found INTEGER NOT NULL,
    malicious INTEGER NOT NULL, suspicious INTEGER NOT NULL,
    harmless INTEGER NOT NULL, undetected INTEGER NOT NULL,
    expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS vt_requests(ts REAL NOT NULL);
"""


class Storage:
    """Кэш репутации хэшей и журнал запросов для соблюдения лимитов."""

    def __init__(self, db_path: Path, clock: Callable[[], float] = time.time) -> None:
        self._path = db_path
        self._clock = clock
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as con:
            con.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path, timeout=5, isolation_level=None)

    def get_cached(self, sha256: str) -> VtReport | None:
        with closing(self._connect()) as con:
            row = con.execute(
                "SELECT found, malicious, suspicious, harmless, undetected "
                "FROM vt_cache WHERE sha256=? AND expires_at>?",
                (sha256, self._clock()),
            ).fetchone()
        if row is None:
            return None
        found, malicious, suspicious, harmless, undetected = row
        status = VtStatus.FOUND if found else VtStatus.NOT_FOUND
        return VtReport(status, malicious, suspicious, harmless, undetected)

    def put_cached(self, sha256: str, report: VtReport, ttl: float) -> None:
        with closing(self._connect()) as con:
            con.execute(
                "INSERT OR REPLACE INTO vt_cache VALUES (?,?,?,?,?,?,?)",
                (sha256, int(report.status is VtStatus.FOUND), report.malicious,
                 report.suspicious, report.harmless, report.undetected,
                 self._clock() + ttl),
            )

    def try_acquire(self, per_minute: int | None, per_day: int | None) -> bool:
        """Атомарно резервирует запрос, если лимиты позволяют. None — лимита нет."""
        now = self._clock()
        with closing(self._connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute("DELETE FROM vt_requests WHERE ts < ?", (now - 86400,))
                last_minute = con.execute(
                    "SELECT COUNT(*) FROM vt_requests WHERE ts >= ?", (now - 60,)
                ).fetchone()[0]
                last_day = con.execute("SELECT COUNT(*) FROM vt_requests").fetchone()[0]
                allowed = (per_minute is None or last_minute < per_minute) and (
                    per_day is None or last_day < per_day
                )
                if allowed:
                    con.execute("INSERT INTO vt_requests(ts) VALUES (?)", (now,))
                con.execute("COMMIT")
                return allowed
            except Exception:
                con.execute("ROLLBACK")
                raise