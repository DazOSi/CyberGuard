import logging
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..config import ScanConfig
from ._proc import Runner, run_command

log = logging.getLogger(__name__)

_EXE = ".exe" if sys.platform == "win32" else ""
_MAIN = ("main.cvd", "main.cld")
_DAILY = ("daily.cvd", "daily.cld")
_STATE_NAME = ".last_update_attempt"
HARD_MIN_INTERVAL = 3600.0   # ClamAV просит проверять обновления не чаще раза в час


def default_data_dir() -> Path:
    """Папка данных текущего пользователя (база сигнатур не в папке программы)."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "CyberGuardHome"
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "cyberguard-home"


def bundled_dir() -> Path:
    """vendor/clamav рядом с приложением; в собранном PyInstaller-приложении — внутри _MEIPASS."""
    root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[3]))
    return root / "vendor" / "clamav"


def database_ready(db_dir: Path) -> bool:
    return (any((db_dir / n).is_file() for n in _MAIN)
            and any((db_dir / n).is_file() for n in _DAILY))


@dataclass(frozen=True, slots=True)
class ClamAvRuntime:
    clamscan: str
    freshclam: str | None
    db_dir: Path | None          # None — база системная, ею управляет не наше приложение

    @property
    def manages_database(self) -> bool:
        return self.db_dir is not None and self.freshclam is not None


def find_runtime(config: ScanConfig) -> ClamAvRuntime | None:
    bundle = config.clamav_bundle_dir or bundled_dir()
    bundled_scan = bundle / f"clamscan{_EXE}"

    if config.clamav_path:
        clamscan = config.clamav_path
    elif bundled_scan.is_file():
        clamscan = str(bundled_scan)
    else:
        clamscan = shutil.which("clamscan")
    if not clamscan:
        return None

    sibling = Path(clamscan).with_name(f"freshclam{_EXE}")
    freshclam = str(sibling) if sibling.is_file() else shutil.which("freshclam")

    is_bundled = Path(clamscan) == bundled_scan
    db_dir = config.clamav_db_dir or (default_data_dir() / "clamav-db" if is_bundled else None)
    if db_dir is not None:
        db_dir = Path(os.path.abspath(db_dir))      # всегда абсолютный путь
    return ClamAvRuntime(clamscan, freshclam, db_dir)


@dataclass(frozen=True, slots=True)
class UpdateResult:
    ran: bool        # запускался ли freshclam
    ok: bool         # можно ли после этого проверять файлы (база на месте)
    message: str     # понятный текст для интерфейса


def _read_state(path: Path) -> float | None:
    try:
        return float(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def update_database(
    runtime: ClamAvRuntime,
    *,
    interval: float,
    runner: Runner = run_command,
    now: Callable[[], float] = time.time,
    timeout: float = 1800.0,
) -> UpdateResult:
    """Обновляет базу через freshclam. Вызывайте в фоновом потоке, не в потоке интерфейса."""
    db_dir = runtime.db_dir
    if db_dir is None or runtime.freshclam is None:
        return UpdateResult(False, True, "База сигнатур обновляется самой системой.")
    try:
        db_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return UpdateResult(False, False, "Не удалось создать папку для базы сигнатур.")

    ready = database_ready(db_dir)
    wait = max(HARD_MIN_INTERVAL, interval) if ready else HARD_MIN_INTERVAL
    state = db_dir / _STATE_NAME
    last = _read_state(state)
    if last is not None and now() - last < wait:
        return UpdateResult(False, ready, "Обновление пока не нужно: базу проверяли недавно.")

    conf = db_dir / "freshclam.conf"
    try:
        conf.write_text(
            f"DatabaseDirectory {db_dir}\n"
            "DatabaseMirror database.clamav.net\n"
            "ConnectTimeout 30\n"
            "ReceiveTimeout 120\n",
            encoding="utf-8",
        )
        state.write_text(str(now()), encoding="utf-8")   # попытку фиксируем заранее
    except OSError:
        return UpdateResult(False, ready, "Не удалось подготовить обновление базы сигнатур.")

    cmd = [runtime.freshclam, f"--config-file={conf}", f"--datadir={db_dir}", "--stdout"]
    try:
        proc = runner(cmd, timeout)
    except subprocess.TimeoutExpired:
        return UpdateResult(True, ready, "Обновление базы сигнатур не уложилось по времени.")
    except OSError:
        return UpdateResult(True, ready, "Не удалось запустить обновление базы сигнатур.")

    if proc.returncode == 0:
        return UpdateResult(True, database_ready(db_dir), "База сигнатур обновлена или уже актуальна.")
    log.warning("freshclam: код %s: %s", proc.returncode, (proc.stdout or proc.stderr).strip()[-300:])
    if database_ready(db_dir):
        return UpdateResult(True, True, "Не удалось обновить базу сигнатур, используется прежняя.")
    return UpdateResult(True, False, "Не удалось загрузить базу сигнатур. Проверьте подключение к интернету.")


def main() -> int:
    """Обновить базу ClamAV вручную."""
    config = ScanConfig.from_env()
    runtime = find_runtime(config)

    if runtime is None:
        print("ClamAV не найден.")
        return 1

    result = update_database(
        runtime,
        interval=config.clamav_update_interval,
    )
    print(result.message)
    return 0 if result.ok else 1