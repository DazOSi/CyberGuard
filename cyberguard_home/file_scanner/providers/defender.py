import logging
import os
import re
import subprocess
import sys
from pathlib import Path

from ..models import Finding, ProviderReport
from ._proc import Runner, run_command

log = logging.getLogger(__name__)
_THREAT_RE = re.compile(r"^\s*Threat\s*:\s*(?P<name>.+?)\s*$", re.MULTILINE)


def find_mpcmdrun() -> str | None:
    if sys.platform != "win32":
        return None
    program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    platform_dir = program_data / "Microsoft" / "Windows Defender" / "Platform"
    if platform_dir.is_dir():
        def version_key(p: Path) -> tuple[int, ...]:
            return tuple(int(x) for x in re.findall(r"\d+", p.parent.name))
        found = sorted(platform_dir.glob("*/MpCmdRun.exe"), key=version_key, reverse=True)
        if found:
            return str(found[0])
    legacy = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe"
    return str(legacy) if legacy.is_file() else None


class WindowsDefenderProvider:
    """Проверка встроенным антивирусом Windows. Только чтение: файл не удаляется и не отправляется."""
    name = "defender"

    def __init__(self, executable: str, *, timeout: float = 120.0, runner: Runner = run_command) -> None:
        self._exe = executable
        self._timeout = timeout
        self._runner = runner

    def _unavailable(self, note: str) -> ProviderReport:
        return ProviderReport(self.name, False, note=note)

    def check(self, path: Path, sha256: str) -> ProviderReport:
        cmd = [self._exe, "-Scan", "-ScanType", "3", "-File", str(path.resolve()), "-DisableRemediation"]
        try:
            proc = self._runner(cmd, self._timeout)
        except subprocess.TimeoutExpired:
            return self._unavailable("Проверка защитником Windows не уложилась по времени.")
        except OSError:
            return self._unavailable("Не удалось запустить защитник Windows.")

        if proc.returncode == 0:
            return ProviderReport(self.name, True, (Finding(
                "defender_clean", "Защитник Windows угроз не нашёл.", 0),))
        if proc.returncode == 2:
            m = _THREAT_RE.search(proc.stdout)
            return ProviderReport(self.name, True, (Finding(
                "defender_detected",
                "Защитник Windows нашёл в файле вредоносную программу.",
                100,
                "Defender: " + (m["name"] if m else "имя не распознано"),
            ),))
        log.warning("Defender: код %s", proc.returncode)
        return self._unavailable(
            "Защитник Windows не смог проверить файл (возможно, он выключен другим антивирусом).")