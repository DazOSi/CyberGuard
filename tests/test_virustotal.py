from pathlib import Path

import httpx

from cyberguard_home.file_scanner.models import VtStatus
from cyberguard_home.file_scanner.storage import Storage
from cyberguard_home.file_scanner.vt_client import VirusTotalClient
from tests.conftest import SHA_ABC

FOUND_JSON = {"data": {"attributes": {"last_analysis_stats": {
    "malicious": 7, "suspicious": 0, "harmless": 60, "undetected": 10}}}}


def make(tmp_path: Path, handler, key: str | None = "key", clock=None):
    storage = Storage(tmp_path / "c.db", clock=clock) if clock else Storage(tmp_path / "c.db")
    http = httpx.Client(transport=httpx.MockTransport(handler), timeout=5)
    return VirusTotalClient(key, storage, http=http), storage


def test_found_sends_only_hash_via_get(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=FOUND_JSON)

    client, _ = make(tmp_path, handler)
    report = client.lookup(SHA_ABC)
    assert report.status is VtStatus.FOUND and report.malicious == 7
    assert len(seen) == 1
    assert seen[0].method == "GET" and seen[0].url.path.endswith(SHA_ABC)
    assert seen[0].headers["x-apikey"] == "key"
    assert seen[0].content == b""


def test_second_lookup_uses_cache(tmp_path: Path) -> None:
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        return httpx.Response(200, json=FOUND_JSON)

    client, _ = make(tmp_path, handler)
    client.lookup(SHA_ABC)
    assert client.lookup(SHA_ABC).status is VtStatus.FOUND
    assert len(calls) == 1


def test_not_found(tmp_path: Path) -> None:
    client, _ = make(tmp_path, lambda r: httpx.Response(404))
    assert client.lookup(SHA_ABC).status is VtStatus.NOT_FOUND


def test_429_is_not_cached(tmp_path: Path) -> None:
    client, storage = make(tmp_path, lambda r: httpx.Response(429))
    assert client.lookup(SHA_ABC).status is VtStatus.RATE_LIMITED
    assert storage.get_cached(SHA_ABC) is None


def test_bad_key(tmp_path: Path) -> None:
    client, _ = make(tmp_path, lambda r: httpx.Response(401))
    assert client.lookup(SHA_ABC).status is VtStatus.BAD_KEY


def test_timeout_is_handled(tmp_path: Path) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timeout")

    client, _ = make(tmp_path, handler)
    assert client.lookup(SHA_ABC).status is VtStatus.ERROR


def test_garbage_json_is_handled(tmp_path: Path) -> None:
    client, _ = make(tmp_path, lambda r: httpx.Response(200, text="not json"))
    assert client.lookup(SHA_ABC).status is VtStatus.ERROR


def test_no_key_makes_no_request(tmp_path: Path) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise AssertionError("не должно быть запросов без ключа")

    client, _ = make(tmp_path, handler, key=None)
    assert client.lookup(SHA_ABC).status is VtStatus.NO_KEY


def test_per_minute_quota(tmp_path: Path) -> None:
    now = [1_000_000.0]
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        return httpx.Response(404)

    client, _ = make(tmp_path, handler, clock=lambda: now[0])
    hashes = [f"{i:064x}" for i in range(5)]
    statuses = [client.lookup(h).status for h in hashes]
    assert statuses[:4] == [VtStatus.NOT_FOUND] * 4
    assert statuses[4] is VtStatus.RATE_LIMITED
    assert len(calls) == 4                      # пятый запрос не отправлялся

    now[0] += 61
    assert client.lookup(hashes[4]).status is VtStatus.NOT_FOUND
    assert len(calls) == 5


def test_premium_has_no_local_quota(tmp_path: Path) -> None:
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        return httpx.Response(404)

    storage = Storage(tmp_path / "c.db")
    http = httpx.Client(transport=httpx.MockTransport(handler), timeout=5)
    client = VirusTotalClient("key", storage, http=http, per_minute=None, per_day=None)
    statuses = [client.lookup(f"{i:064x}").status for i in range(10)]
    assert statuses == [VtStatus.NOT_FOUND] * 10 and len(calls) == 10