import subprocess
from collections.abc import Callable, Sequence

Runner = Callable[[Sequence[str], float], "subprocess.CompletedProcess[str]"]


def run_command(cmd: Sequence[str], timeout: float) -> "subprocess.CompletedProcess[str]":
    """Запуск без оболочки (shell), с таймаутом и без мигающего окна на Windows."""
    return subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )