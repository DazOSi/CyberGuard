"""
Скачивает официальную портативную сборку ClamAV для Windows (x64) в vendor/clamav
и загружает базу сигнатур. Запуск:  python scripts/setup_clamav.py
"""
import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import httpx

API_LATEST = "https://api.github.com/repos/Cisco-Talos/clamav/releases/latest"
ASSET_RE = re.compile(r"^clamav-.+\.win\.x64\.zip$")
ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "vendor" / "clamav"
TIMEOUT = httpx.Timeout(30.0, read=180.0)
HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "cyberguard-home-setup"}


class SetupError(Exception):
    """Понятная пользователю ошибка установки."""


def pick_asset(assets: list[dict]) -> dict:
    for asset in assets:
        if ASSET_RE.match(str(asset.get("name", ""))):
            return asset
    names = ", ".join(str(a.get("name")) for a in assets) or "список пуст"
    raise SetupError(
        "В последнем релизе не нашёлся портативный ZIP для Windows x64. "
        f"Скачайте его вручную с https://www.clamav.net/downloads . Файлы релиза: {names}")


def verify_digest(actual_sha256: str, asset: dict) -> bool:
    """True — хэш сверен с GitHub; False — эталона нет; SetupError — не совпало."""
    digest = str(asset.get("digest") or "")
    if not digest.startswith("sha256:"):
        return False
    if digest.removeprefix("sha256:").lower() != actual_sha256.lower():
        raise SetupError("Контрольная сумма скачанного файла не совпала. Файл повреждён, повторите попытку.")
    return True


def install_from_zip(zip_path: Path, dest: Path) -> None:
    """Распаковывает архив и целиком заменяет папку dest (без смешивания версий DLL)."""
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(tmp)
        payload = next((p.parent for p in Path(tmp).rglob("clamscan.exe")), None)
        if payload is None or not (payload / "freshclam.exe").is_file():
            raise SetupError("В архиве не нашлись clamscan.exe и freshclam.exe.")
        try:
            if dest.exists():
                shutil.rmtree(dest)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(payload, dest)
        except PermissionError as exc:
            raise SetupError("Не удалось заменить файлы. Закройте приложение и ClamAV и повторите.") from exc


def fetch_latest_release() -> dict:
    response = httpx.get(API_LATEST, headers=HEADERS, timeout=TIMEOUT, follow_redirects=True)
    response.raise_for_status()
    return response.json()


def download(url: str, target: Path) -> str:
    """Скачивает файл по частям, возвращает SHA-256."""
    digest = hashlib.sha256()
    with httpx.stream("GET", url, headers={"User-Agent": HEADERS["User-Agent"]},
                      timeout=TIMEOUT, follow_redirects=True) as response:
        response.raise_for_status()
        total = int(response.headers.get("content-length") or 0)
        done = 0
        last_percent = -10
        with target.open("wb") as out:
            for chunk in response.iter_bytes(1024 * 1024):
                out.write(chunk)
                digest.update(chunk)
                done += len(chunk)
                if total and (percent := done * 100 // total) >= last_percent + 10:
                    last_percent = percent
                    print(f"  {percent}%")
    return digest.hexdigest()


def write_version_file(dest: Path, tag: str, asset: dict, sha256: str, verified: bool) -> None:
    lines = [
        f"ClamAV {tag}",
        f"Файл: {asset.get('name')}",
        f"Источник: {asset.get('browser_download_url')}",
        f"SHA-256: {sha256} ({'сверено с GitHub' if verified else 'эталон не найден'})",
        f"Установлено: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "Лицензия: GPLv2 (см. COPYING). Храните эту запись для раздела сторонних компонентов.",
    ]
    (dest / "VERSION.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Установка ClamAV в vendor/clamav")
    parser.add_argument("--no-update", action="store_true", help="не загружать базу сигнатур")
    args = parser.parse_args(argv)

    if sys.platform != "win32":
        print("Скрипт рассчитан на Windows. На Linux и macOS установите ClamAV через apt, dnf или brew.")
        return 1

    try:
        release = fetch_latest_release()
        asset = pick_asset(release.get("assets", []))
        tag = str(release.get("tag_name", "?"))
        print(f"Скачиваю {asset['name']} ({tag})…")
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / asset["name"]
            sha256 = download(asset["browser_download_url"], zip_path)
            verified = verify_digest(sha256, asset)
            install_from_zip(zip_path, DEST)
    except (SetupError, httpx.HTTPError, zipfile.BadZipFile, OSError) as exc:
        print(f"Не получилось: {exc}")
        return 1

    write_version_file(DEST, tag, asset, sha256, verified)
    print(f"ClamAV установлен: {DEST}")
    if not verified:
        print(f"Контрольная сумма не сверялась автоматически. SHA-256: {sha256}")

    if args.no_update:
        return 0
    print("Загружаю базу сигнатур. Это нужно один раз и может занять несколько минут…")
    update = subprocess.run(
        [sys.executable, "-m", "cyberguard_home.file_scanner.providers.clamav_runtime"],
        cwd=ROOT, check=False)
    return update.returncode


if __name__ == "__main__":
    raise SystemExit(main())