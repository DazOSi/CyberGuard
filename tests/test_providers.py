import hashlib
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from cyberguard_home.file_scanner import ScanConfig, VtReport, VtStatus
from cyberguard_home.file_scanner.providers import build_providers
from cyberguard_home.file_scanner.providers.clamav import ClamAvProvider
from cyberguard_home.file_scanner.providers.defender import WindowsDefenderProvider, find_mpcmdrun
from cyberguard_home.file_scanner.providers.local_hashes import LocalHashListProvider
from cyberguard_home.file_scanner.providers.virustotal import VirusTotalProvider
from tests.conftest import EICAR, SHA_ABC


def proc(code: int, out: str = "", err: str = "") -> "subprocess.CompletedProcess[str]":
    return subprocess.CompletedProcess([], code, out, err)


class FakeRunner:
    def __init__(self, result) -> None:
        self.result, self.calls, self.stdin_paths = result, [], []

    def __call__(self, cmd, timeout, stdin_path=None):
        self.calls.append((list(cmd), timeout))
        self.stdin_paths.append(stdin_path)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result

# ---------- локальная база хэшей ----------
def test_local_hash_list(tmp_path: Path) -> None:
    sha = hashlib.sha256(EICAR).hexdigest()
    lst = tmp_path / "bl.txt"
    lst.write_text(f"# комментарий\n\nне-хэш\n{sha.upper()}  Test.Eicar\n", encoding="utf-8")
    provider = LocalHashListProvider(lst)
    hit = provider.check(tmp_path / "x", sha)
    assert hit.available and hit.findings[0].points == 100
    assert "Test.Eicar" in hit.findings[0].technical
    miss = provider.check(tmp_path / "x", SHA_ABC)
    assert miss.available and not miss.findings


# ---------- ClamAV ----------
def test_clamav_detected() -> None:
    sample = Path("/cg/sample.txt")          # не зависит от кириллицы в папке временных файлов
    runner = FakeRunner(proc(1, "/cg/sample.txt: Eicar-Signature FOUND\n"))
    report = ClamAvProvider("clamscan", runner=runner).check(sample, SHA_ABC)
    assert report.available and report.findings[0].points == 100
    assert "Eicar-Signature" in report.findings[0].technical
    cmd = runner.calls[0][0]
    assert cmd[0] == "clamscan" and Path(cmd[-1]).is_absolute()
    assert runner.stdin_paths[0] is None


def test_clamav_uses_stdin_for_non_ascii_paths(tmp_path: Path) -> None:
    sample = tmp_path / "счёт.txt"
    sample.write_bytes(b"x")
    runner = FakeRunner(proc(0))
    ClamAvProvider("clamscan", runner=runner).check(sample, SHA_ABC)
    assert runner.calls[0][0][-1] == "-" and runner.stdin_paths[0] == sample


@pytest.mark.parametrize("result", [proc(2, err="no database"), subprocess.TimeoutExpired("c", 1), FileNotFoundError()])
def test_clamav_failures_are_not_clean(tmp_path: Path, result) -> None:
    report = ClamAvProvider("clamscan", runner=FakeRunner(result)).check(tmp_path / "a", SHA_ABC)
    assert not report.available and report.note and not report.findings


# ---------- Defender ----------
def test_defender_detected(tmp_path: Path) -> None:
    out = "Threat                  : Virus:DOS/EICAR_Test_File\n"
    report = WindowsDefenderProvider("MpCmdRun.exe", runner=FakeRunner(proc(2, out))).check(tmp_path / "a", SHA_ABC)
    assert report.available and report.findings[0].points == 100
    assert "EICAR_Test_File" in report.findings[0].technical


def test_defender_clean_and_failure(tmp_path: Path) -> None:
    ok = WindowsDefenderProvider("m", runner=FakeRunner(proc(0))).check(tmp_path / "a", SHA_ABC)
    assert ok.available and ok.findings[0].points == 0
    bad = WindowsDefenderProvider("m", runner=FakeRunner(proc(5))).check(tmp_path / "a", SHA_ABC)
    assert not bad.available


def test_defender_not_searched_outside_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert find_mpcmdrun() is None


# ---------- VirusTotal как провайдер ----------
class FakeClient:
    def __init__(self, report: VtReport) -> None:
        self.report = report

    def lookup(self, sha256: str) -> VtReport:
        return self.report


@pytest.mark.parametrize("malicious,expected", [(12, 100), (2, 40), (0, 0)])
def test_vt_provider_scoring(tmp_path: Path, malicious: int, expected: int) -> None:
    report = VtReport(VtStatus.FOUND, malicious=malicious, harmless=50)
    result = VirusTotalProvider(FakeClient(report)).check(tmp_path / "a", SHA_ABC)
    assert result.available and sum(f.points for f in result.findings) == expected


def test_vt_provider_rate_limit_is_unavailable(tmp_path: Path) -> None:
    result = VirusTotalProvider(FakeClient(VtReport(VtStatus.RATE_LIMITED))).check(tmp_path / "a", SHA_ABC)
    assert not result.available and "позже" in result.note


# ---------- запрет бесплатного VirusTotal без лицензии ----------
def _close(providers) -> None:
    for p in providers:
        if hasattr(p, "close"):
            p.close()


def test_vt_disabled_without_license(config: ScanConfig) -> None:
    providers = build_providers(replace(config, vt_api_key="key", vt_license="none"))
    assert all(p.name != "virustotal" for p in providers)


def test_vt_enabled_with_license(config: ScanConfig) -> None:
    providers = build_providers(replace(config, vt_api_key="key", vt_license="premium",
                                        vt_per_minute=None, vt_per_day=None))
    try:
        assert any(p.name == "virustotal" for p in providers)
    finally:
        _close(providers)


def test_offline_mode_disables_vt(config: ScanConfig) -> None:
    providers = build_providers(replace(config, vt_api_key="key", vt_license="premium", online_lookup=False))
    assert all(p.name != "virustotal" for p in providers)