"""Streaming HMAC-SHA256 integrity manifests."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path

from crypto_vault.crypto.kdf import derive_key, new_salt

CHUNK_SIZE = 64 * 1024

def _write_atomic(path: Path, data: str, overwrite: bool) -> None:
    if path.is_symlink():
        raise ValueError("Signature destination must not be a symbolic link")
    if path.exists() and not overwrite:
        raise FileExistsError(path)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

def hmac_file(path: Path, key: bytes) -> str:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            mac.update(chunk)
    return mac.hexdigest()

def create_signature(path: Path, signature_path: Path, passphrase: str, overwrite: bool = False) -> Path:
    path, signature_path = Path(path), Path(signature_path)
    if path.resolve() == signature_path.resolve():
        raise ValueError("Source and signature destinations must differ")
    salt = new_salt()
    digest = hmac_file(path, derive_key(passphrase, salt))
    manifest = {"version": 1, "kdf": "argon2id", "salt": salt.hex(), "hmac_sha256": digest}
    _write_atomic(signature_path, json.dumps(manifest, indent=2) + "\n", overwrite)
    return signature_path

def verify_signature(path: Path, signature_path: Path, passphrase: str) -> bool:
    try:
        manifest = json.loads(Path(signature_path).read_text(encoding="utf-8"))
        salt = bytes.fromhex(manifest["salt"])
        expected = manifest["hmac_sha256"]
        actual = hmac_file(path, derive_key(passphrase, salt, manifest["kdf"]))
        return hmac.compare_digest(actual, expected)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return False
