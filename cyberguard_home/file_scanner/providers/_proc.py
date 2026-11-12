import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol


class Runner(Protocol):
    def __call__(
        self, cmd: Sequence[str], timeout: float, stdin_path: Path | None = None
    ) -> "subprocess.CompletedProcess[str]": ...


def run_command(
    cmd: Sequence[str], timeout: float, stdin_path: Path | None = None
) -> "subprocess.CompletedProcess[str]":
    """Запуск без оболочки (shell), с таймаутом и без мигающего окна на Windows.
    Если задан stdin_path, содержимое этого файла подаётся программе на стандартный ввод."""
    options = dict(
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, check=False, shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if stdin_path is None:
        return subprocess.run(list(cmd), **options)
    with stdin_path.open("rb") as handle:
        return subprocess.run(list(cmd), stdin=handle, **options)