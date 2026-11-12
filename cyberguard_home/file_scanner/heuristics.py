import zipfile
from enum import StrEnum
from pathlib import Path

import olefile

from .models import Finding

EXECUTABLE_EXTS = frozenset({
    ".exe", ".scr", ".com", ".bat", ".cmd", ".msi", ".ps1", ".vbs", ".js",
    ".jse", ".wsf", ".jar", ".lnk", ".dll", ".pif", ".hta", ".cpl",
})
DECOY_EXTS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
    ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip", ".rar",
})
OOXML_EXTS = frozenset({
    ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm",
    ".pptx", ".pptm", ".potx", ".potm",
})
OOXML_NO_MACROS = frozenset({".docx", ".dotx", ".xlsx", ".xltx", ".pptx", ".potx"})
OLE_OFFICE_EXTS = frozenset({".doc", ".dot", ".xls", ".xlt", ".ppt", ".pot"})

_MACHO = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
_OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")


class FileKind(StrEnum):
    EXECUTABLE = "executable"
    ZIP = "zip"
    OLE = "ole"
    OTHER = "other"


def sniff_kind(path: Path) -> FileKind:
    """Тип по содержимому (первые байты), а не по расширению."""
    with path.open("rb") as f:
        head = f.read(8)
    if head[:2] == b"MZ" or head[:4] == b"\x7fELF" or head[:4] in _MACHO:
        return FileKind.EXECUTABLE
    if head[:4] == b"PK\x03\x04":
        return FileKind.ZIP
    if head[:8] == _OLE_MAGIC:
        return FileKind.OLE
    return FileKind.OTHER


def _is_executable(path: Path, kind: FileKind) -> bool:
    return kind is FileKind.EXECUTABLE or path.suffix.lower() in EXECUTABLE_EXTS


def check_double_extension(path: Path) -> list[Finding]:
    suffixes = [s.lower() for s in path.suffixes]
    if len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_EXTS and suffixes[-2] in DECOY_EXTS:
        return [Finding(
            "double_extension",
            f"Имя файла «{path.name}» выглядит как документ или картинка, "
            "но на самом деле это программа. Так мошенники прячут вирусы.",
            60, f"suffixes={suffixes}",
        )]
    return []


def check_disguised_executable(path: Path, kind: FileKind) -> list[Finding]:
    suffix = path.suffix.lower()
    if kind is FileKind.EXECUTABLE and suffix in DECOY_EXTS:
        return [Finding(
            "disguised_executable",
            f"Файл выглядит как «{suffix}», но внутри — программа. "
            "Это приём, чтобы обманом заставить вас запустить вирус.",
            60, "magic bytes: executable",
        )]
    return []


def check_executable_in_downloads(
    path: Path, kind: FileKind, downloads_dirs: tuple[Path, ...]
) -> list[Finding]:
    if not _is_executable(path, kind):
        return []
    resolved = path.resolve()
    if any(resolved.is_relative_to(d.resolve()) for d in downloads_dirs):
        return [Finding(
            "exe_in_downloads",
            "Это программа, скачанная из интернета. "
            "Запускайте её, только если полностью доверяете источнику.",
            20,
        )]
    return []


def check_office_macros(path: Path, kind: FileKind) -> list[Finding]:
    suffix = path.suffix.lower()
    has_macros = False
    try:
        if kind is FileKind.ZIP and suffix in OOXML_EXTS:
            with zipfile.ZipFile(path) as zf:
                has_macros = any(n.lower().endswith("vbaproject.bin") for n in zf.namelist())
        elif kind is FileKind.OLE and suffix in OLE_OFFICE_EXTS:
            ole = olefile.OleFileIO(str(path))
            try:
                has_macros = any(
                    entry[0].upper() == "MACROS" or any("VBA" in p.upper() for p in entry)
                    for entry in ole.listdir()
                )
            finally:
                ole.close()
    except (zipfile.BadZipFile, OSError, ValueError):
        return []
    if not has_macros:
        return []
    if suffix in OOXML_NO_MACROS:
        return [Finding(
            "office_macros",
            "Документ выдаёт себя за обычный, но содержит макросы — это очень подозрительно.",
            60, "vbaProject.bin inside a macro-free extension",
        )]
    return [Finding(
        "office_macros",
        "В документе есть макросы — встроенные мини-программы. "
        "Мошенники часто используют их, чтобы заразить компьютер.",
        40, "VBA macros",
    )]


def check_encrypted_archive(path: Path, kind: FileKind) -> list[Finding]:
    """Только ZIP: заголовки читаются, содержимое не распаковывается (защита от zip-бомб)."""
    if kind is not FileKind.ZIP or path.suffix.lower() in OOXML_EXTS:
        return []
    try:
        with zipfile.ZipFile(path) as zf:
            encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
    except (zipfile.BadZipFile, OSError):
        return []
    if encrypted:
        return [Finding(
            "encrypted_archive",
            "Архив защищён паролем, поэтому защита не может заглянуть внутрь. "
            "Мошенники часто так прячут вирусы.",
            30, "zip encryption flag",
        )]
    return []


def run_heuristics(path: Path, downloads_dirs: tuple[Path, ...]) -> list[Finding]:
    kind = sniff_kind(path)
    return [
        *check_double_extension(path),
        *check_disguised_executable(path, kind),
        *check_executable_in_downloads(path, kind, downloads_dirs),
        *check_office_macros(path, kind),
        *check_encrypted_archive(path, kind),
    ]