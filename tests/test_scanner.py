import hashlib
from pathlib import Path
from dataclasses import replace

import httpx
import pytest

from cyberguard_home.file_scanner import FileScanError, FileScanner, Finding, ProviderReport, ScanConfig, Verdict
from cyberguard_home.file_scanner.providers.virustotal import VirusTotalProvider
from cyberguard_home.file_scanner.storage import Storage
from cyberguard_home.file_scanner.vt_client import VirusTotalClient


class FakeProvider:
    name = "fake"

    def __init__(self, report: ProviderReport) -> None:
        self.report = report

    def check(self, path: Path, sha256: str) -> ProviderReport:
        return self.report


class BoomProvider:
    name = "boom"

    def check(self, path: Path, sha256: str) -> ProviderReport:
        raise RuntimeError("сбой движка")


CLEAN = ProviderReport("fake", True, (Finding("fake_clean", "Угроз не найдено.", 0),))
DETECTED = ProviderReport("fake", True, (Finding("fake_bad", "Движок нашёл угрозу.", 100, "Fake.Threat"),))
UNAVAILABLE = ProviderReport("fake", False, note="Проверка не выполнена: нет связи.")


def scanner(config: ScanConfig, *providers) -> FileScanner:
    return FileScanner(config, providers=list(providers))


def test_eicar_is_dangerous_by_yara_alone(config: ScanConfig, tmp_path: Path) -> None:
    rules_dir = tmp_path / "test_rules"
    rules_dir.mkdir()

    rule = rules_dir / "test.yar"
    rule.write_text(
        """
        rule CG_Test_Marker {
            meta:
                score = 100
            strings:
                $marker = "CYBERGUARD_TEST_MALWARE_MARKER"
            condition:
                $marker
        }
        """,
        encoding="utf-8",
    )

    f = tmp_path / "test.txt"
    f.write_text("CYBERGUARD_TEST_MALWARE_MARKER", encoding="utf-8")

    test_config = replace(config, rules_dir=rules_dir)
    result = scanner(test_config).scan(f)

    assert result.verdict is Verdict.DANGEROUS
    assert result.reasons and result.recommendation
    assert not result.complete                     # движков нет — честно сообщаем


def test_clean_file_is_safe_and_complete(config: ScanConfig, tmp_path: Path) -> None:
    f = tmp_path / "note.txt"
    f.write_text("обычный текст")
    result = scanner(config, FakeProvider(CLEAN)).scan(f)
    assert result.verdict is Verdict.SAFE and result.complete


def test_provider_detection_is_dangerous(config: ScanConfig, tmp_path: Path) -> None:
    f = tmp_path / "note.txt"
    f.write_text("текст")
    result = scanner(config, FakeProvider(DETECTED)).scan(f)
    assert result.verdict is Verdict.DANGEROUS and "Fake.Threat" in result.technical


def test_unavailable_provider_is_reported_honestly(config: ScanConfig, tmp_path: Path) -> None:
    f = tmp_path / "note.txt"
    f.write_text("текст")
    result = scanner(config, FakeProvider(UNAVAILABLE)).scan(f)
    assert result.verdict is Verdict.SAFE and not result.complete
    assert "нет связи" in result.skipped_checks[0] and "повторите" in result.recommendation


def test_crashing_provider_does_not_break_scan(config: ScanConfig, tmp_path: Path) -> None:
    f = tmp_path / "note.txt"
    f.write_text("текст")
    result = scanner(config, BoomProvider(), FakeProvider(DETECTED)).scan(f)
    assert result.verdict is Verdict.DANGEROUS and not result.complete


def test_no_providers_is_flagged(config: ScanConfig, tmp_path: Path) -> None:
    f = tmp_path / "note.txt"
    f.write_text("текст")
    result = scanner(config).scan(f)
    assert not result.complete and any("ClamAV" in s for s in result.skipped_checks)


def test_double_extension_in_downloads_is_dangerous(config: ScanConfig, tmp_path: Path) -> None:
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    f = downloads / "invoice.pdf.exe"
    f.write_bytes(b"MZ" + b"\x00" * 64)
    assert scanner(config, FakeProvider(CLEAN)).scan(f).verdict is Verdict.DANGEROUS   # 60 + 20


def test_only_hash_leaves_the_computer(config: ScanConfig, tmp_path: Path) -> None:
    payload = b"CyberGuard privacy test file"
    f = tmp_path / "privacy_test.txt"
    f.write_bytes(payload)

    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(404)

    http = httpx.Client(transport=httpx.MockTransport(handler))
    provider = VirusTotalProvider(
        VirusTotalClient("key", Storage(config.db_path), http=http)
    )
    scanner(config, provider).scan(f)

    sha = hashlib.sha256(payload).hexdigest()

    assert len(seen) == 1
    assert seen[0].method == "GET"
    assert seen[0].url.path == f"/api/v3/files/{sha}"
    assert seen[0].content == b""


def test_missing_file_and_directory(config: ScanConfig, tmp_path: Path) -> None:
    s = scanner(config)
    with pytest.raises(FileScanError):
        s.scan(tmp_path / "нет-такого.txt")
    with pytest.raises(FileScanError):
        s.scan(tmp_path)