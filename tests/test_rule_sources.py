import json
import re

import pytest

from tests.conftest import PROJECT_RULES

_BAD = re.compile(r"(?i)(\bNC\b|non-?commercial|\bA?GPL|\bCC[- ]BY[- ]NC)")
_REGISTRY = json.loads((PROJECT_RULES / "sources.json").read_text(encoding="utf-8"))


def test_registry_has_only_allowed_licenses() -> None:
    allowed = set(_REGISTRY["allowed_licenses"])
    assert all(s["license"] in allowed for s in _REGISTRY["sources"])


def test_every_third_party_dir_is_registered() -> None:
    third = PROJECT_RULES / "third_party"
    if not third.is_dir():
        pytest.skip("third_party не установлен")
    registered = {s["dir"] for s in _REGISTRY["sources"]}
    unknown = {p.name for p in third.iterdir() if p.is_dir()} - registered
    assert not unknown, f"Не внесены в sources.json (проверьте лицензии): {unknown}"


def test_no_noncommercial_or_gpl_license_in_rule_meta() -> None:
    offenders: list[str] = []
    for f in [*PROJECT_RULES.rglob("*.yar"), *PROJECT_RULES.rglob("*.yara")]:
        text = f.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r'license\s*=\s*"([^"]+)"', text):
            if _BAD.search(m.group(1)):
                offenders.append(f"{f.relative_to(PROJECT_RULES)}: {m.group(1)}")
    assert not offenders, "Правила с неподходящей лицензией:\n" + "\n".join(offenders[:20])