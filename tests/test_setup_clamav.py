import importlib.util
import zipfile
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "setup_clamav", Path(__file__).resolve().parents[1] / "scripts" / "setup_clamav.py")
setup = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(setup)


def make_zip(path: Path, names: list[str]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, b"x")


def test_pick_asset_chooses_x64_zip() -> None:
    assets = [{"name": "clamav-1.5.0.win.x64.msi"}, {"name": "clamav-1.5.0.win.x64.zip"}]
    assert setup.pick_asset(assets)["name"].endswith("win.x64.zip")


def test_pick_asset_without_match_explains() -> None:
    with pytest.raises(setup.SetupError, match="clamav.net"):
        setup.pick_asset([{"name": "source.tar.gz"}])


def test_digest_verification() -> None:
    assert setup.verify_digest("ab", {"digest": "sha256:AB"}) is True
    assert setup.verify_digest("ab", {}) is False
    with pytest.raises(setup.SetupError):
        setup.verify_digest("ab", {"digest": "sha256:cd"})


def test_install_replaces_folder_completely(tmp_path: Path) -> None:
    archive = tmp_path / "c.zip"
    make_zip(archive, ["clamav-1.5.0.win.x64/clamscan.exe", "clamav-1.5.0.win.x64/freshclam.exe",
                       "clamav-1.5.0.win.x64/libclamav.dll"])
    dest = tmp_path / "vendor" / "clamav"
    dest.mkdir(parents=True)
    (dest / "old.dll").write_bytes(b"old")
    setup.install_from_zip(archive, dest)
    assert (dest / "clamscan.exe").is_file() and (dest / "libclamav.dll").is_file()
    assert not (dest / "old.dll").exists()           # версии не смешиваются


def test_broken_archive_keeps_existing_install(tmp_path: Path) -> None:
    archive = tmp_path / "bad.zip"
    make_zip(archive, ["readme.txt"])
    dest = tmp_path / "clamav"
    dest.mkdir()
    (dest / "keep.dll").write_bytes(b"x")
    with pytest.raises(setup.SetupError):
        setup.install_from_zip(archive, dest)
    assert (dest / "keep.dll").is_file()