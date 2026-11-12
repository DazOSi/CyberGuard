import hashlib
import os
from pathlib import Path

from cyberguard_home.file_scanner.hashing import sha256_file
from tests.conftest import SHA_ABC


def test_known_hash(tmp_path: Path) -> None:
    f = tmp_path / "a.bin"
    f.write_bytes(b"abc")
    assert sha256_file(f) == SHA_ABC


def test_chunked_equals_oneshot(tmp_path: Path) -> None:
    data = os.urandom(5 * 1024 * 1024 + 123)
    f = tmp_path / "big.bin"
    f.write_bytes(data)
    assert sha256_file(f, chunk_size=64 * 1024) == hashlib.sha256(data).hexdigest()