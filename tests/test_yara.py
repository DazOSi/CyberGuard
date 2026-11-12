from pathlib import Path

from cyberguard_home.file_scanner.yara_scan import YaraScanner
from tests.conftest import EICAR, PROJECT_RULES


def test_eicar_detected() -> None:
    findings = YaraScanner(PROJECT_RULES).scan_data(
        EICAR,
        filename="eicar.com.txt",
    )
    assert findings and findings[0].points == 100

def test_clean_file_not_flagged(tmp_path: Path) -> None:
    f = tmp_path / "note.txt"
    f.write_text("Привет, это обычный файл")
    assert YaraScanner(PROJECT_RULES).scan(f) == []


def test_broken_rule_is_skipped(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "good.yar").write_text(
        'rule T { meta: score = 80 strings: $a = "HELLO_BAD" condition: $a }'
    )
    (rules / "broken.yar").write_text("rule { это не правило")
    scanner = YaraScanner(rules)
    assert len(scanner.load_errors) == 1
    f = tmp_path / "x.bin"
    f.write_bytes(b"...HELLO_BAD...")
    assert scanner.scan(f)[0].points == 80


def test_empty_rules_dir(tmp_path: Path) -> None:
    (tmp_path / "rules").mkdir()
    scanner = YaraScanner(tmp_path / "rules")
    assert not scanner.available
    assert scanner.scan(tmp_path) == []