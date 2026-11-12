import zipfile
from pathlib import Path

from cyberguard_home.file_scanner.heuristics import run_heuristics

MZ = b"MZ" + b"\x00" * 64


def codes(path: Path, downloads: Path | None = None) -> set[str]:
    dirs = (downloads,) if downloads else ()
    return {f.code for f in run_heuristics(path, dirs)}


def make_zip(path: Path, files: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)


def test_double_extension(tmp_path: Path) -> None:
    f = tmp_path / "счёт.pdf.exe"
    f.write_bytes(MZ)
    assert "double_extension" in codes(f)


def test_version_number_is_not_double_extension(tmp_path: Path) -> None:
    f = tmp_path / "setup.v2.exe"
    f.write_bytes(MZ)
    assert "double_extension" not in codes(f)


def test_disguised_executable(tmp_path: Path) -> None:
    f = tmp_path / "photo.jpg"
    f.write_bytes(MZ)
    assert "disguised_executable" in codes(f)


def test_exe_in_downloads_only(tmp_path: Path) -> None:
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    inside, outside = downloads / "setup.exe", tmp_path / "setup.exe"
    inside.write_bytes(MZ)
    outside.write_bytes(MZ)
    assert "exe_in_downloads" in codes(inside, downloads)
    assert "exe_in_downloads" not in codes(outside, downloads)


def test_docm_with_macros(tmp_path: Path) -> None:
    f = tmp_path / "report.docm"
    make_zip(f, {"[Content_Types].xml": b"<x/>", "word/vbaProject.bin": b"vba"})
    findings = run_heuristics(f, ())
    assert [x.points for x in findings if x.code == "office_macros"] == [40]


def test_docx_with_macros_is_worse(tmp_path: Path) -> None:
    f = tmp_path / "report.docx"
    make_zip(f, {"word/vbaProject.bin": b"vba"})
    assert [x.points for x in run_heuristics(f, ()) if x.code == "office_macros"] == [60]


def test_clean_docx(tmp_path: Path) -> None:
    f = tmp_path / "ok.docx"
    make_zip(f, {"[Content_Types].xml": b"<x/>", "word/document.xml": b"<d/>"})
    assert codes(f) == set()


def test_encrypted_zip(tmp_path: Path) -> None:
    f = tmp_path / "secret.zip"
    with zipfile.ZipFile(f, "w") as zf:
        zf.writestr("a.txt", b"data")
        zf.infolist()[0].flag_bits |= 0x1       # имитируем флаг шифрования
    assert "encrypted_archive" in codes(f)


def test_plain_zip_is_fine(tmp_path: Path) -> None:
    f = tmp_path / "plain.zip"
    make_zip(f, {"a.txt": b"data"})
    assert "encrypted_archive" not in codes(f)