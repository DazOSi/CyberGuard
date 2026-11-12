import logging
import re
import subprocess
from pathlib import Path

from ..models import Finding, ProviderReport
from ._proc import Runner, run_command
from .clamav_runtime import database_ready

log = logging.getLogger(__name__)
_FOUND_RE = re.compile(r"^.*: (?P<name>[^:]+?) FOUND\s*$")


class ClamAvProvider:
    """
    ClamAV запускается как отдельная программа (встроенная в поставку или системная).
    Мы не линкуем libclamav. Файл остаётся на компьютере.
    database_dir задаётся для встроенного ClamAV; None — база по умолчанию (системная).
    """
    name = "clamav"

    def __init__(
        self,
        executable: str,
        *,
        database_dir: Path | None = None,
        timeout: float = 120.0,
        runner: Runner = run_command,
    ) -> None:
        self._exe = executable
        self._db = database_dir
        self._timeout = timeout
        self._runner = runner

    def _unavailable(self, note: str) -> ProviderReport:
        return ProviderReport(self.name, False, note=note)

    def check(self, path: Path, sha256: str) -> ProviderReport:
        if self._db is not None and not database_ready(self._db):
            return self._unavailable(
                "База сигнатур ClamAV ещё не загружена. Подождите окончания обновления и повторите проверку.")

        resolved = path.resolve()
        # Не-ASCII путь передаём через стандартный ввод (clamscan -): так не зависим от кодировки.
        use_stdin = not str(resolved).isascii()

        cmd = [self._exe, "--no-summary", "--stdout"]
        if self._db is not None:
            cmd.append(f"--database={self._db}")
        # Абсолютный путь не может начинаться с «-», поэтому не примется за параметр.
        cmd.append("-" if use_stdin else str(resolved))
        try:
            if use_stdin:
                proc = self._runner(cmd, self._timeout, stdin_path=path)
            else:
                proc = self._runner(cmd, self._timeout)
        except subprocess.TimeoutExpired:
            return self._unavailable("Проверка движком ClamAV не уложилась по времени. Попробуйте ещё раз.")
        except OSError:
            return self._unavailable("Не удалось запустить антивирусный движок ClamAV.")

        if proc.returncode == 0:
            return ProviderReport(self.name, True, (Finding(
                "clamav_clean", "Антивирусный движок ClamAV угроз не нашёл.", 0),))
        if proc.returncode == 1:
            names = [m["name"] for line in proc.stdout.splitlines() if (m := _FOUND_RE.match(line))]
            return ProviderReport(self.name, True, (Finding(
                "clamav_detected",
                "Антивирусный движок ClamAV нашёл в файле вредоносную программу.",
                100,
                "ClamAV: " + (", ".join(names[:3]) or "имя не распознано"),
            ),))
        log.warning("ClamAV: код %s: %s", proc.returncode, proc.stderr.strip()[:200])
        return self._unavailable(
            "Движок ClamAV не смог проверить файл (возможно, не загружена база сигнатур).")