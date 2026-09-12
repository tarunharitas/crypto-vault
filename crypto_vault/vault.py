"""Password-vault service layer."""
import struct
from pathlib import Path

from crypto_vault.crypto.cipher import decrypt_bytes, encrypt_bytes
from crypto_vault.crypto.kdf import derive_key, new_salt
from crypto_vault.db.database import Database
from crypto_vault.exceptions import (
    AuthenticationError,
    InvalidVaultError,
    VaultAlreadyInitializedError,
    VaultNotInitializedError,
)

CANARY = b"CRYPTO_VAULT_CANARY_V1"
LEGACY_AAD_VERSION = 1
CURRENT_AAD_VERSION = 2
MAX_IDENTIFIER_LENGTH = 1024

def _aad(service: str, username: str, version: int) -> bytes:
    if version == LEGACY_AAD_VERSION:
        return f"{service}:{username}".encode()
    if version != CURRENT_AAD_VERSION:
        raise InvalidVaultError("Unsupported credential metadata version")
    service_bytes = service.encode("utf-8")
    username_bytes = username.encode("utf-8")
    return struct.pack(">II", len(service_bytes), len(username_bytes)) + service_bytes + username_bytes

def _validate_identifier(value: str, field: str) -> None:
    if not isinstance(value, str) or not value or len(value) > MAX_IDENTIFIER_LENGTH:
        raise ValueError(f"{field} must be a non-empty string of at most {MAX_IDENTIFIER_LENGTH} characters")

class Vault:
    def __init__(self, path: Path): self.db = Database(path)
    def close(self): self.db.close()
    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    def initialize(self, password: str):
        if self.db.get_meta("salt") is not None: raise VaultAlreadyInitializedError("Vault already initialized")
        salt = new_salt(); key = derive_key(password, salt)
        nonce, encrypted = encrypt_bytes(key, CANARY, b"vault-canary-v1")
        self.db.set_meta_many({"salt": salt, "canary_nonce": nonce, "canary": encrypted, "kdf": b"argon2id"})

    def unlock(self, password: str) -> bytes:
        salt = self.db.get_meta("salt")
        if salt is None: raise VaultNotInitializedError("Run `cryptovault vault init` first")
        kdf_value = self.db.get_meta("kdf")
        nonce = self.db.get_meta("canary_nonce")
        canary = self.db.get_meta("canary")
        if len(salt) != 16 or kdf_value is None or nonce is None or canary is None or len(nonce) != 12 or len(canary) < 16:
            raise AuthenticationError("Vault metadata is invalid or incomplete")
        try:
            kdf = kdf_value.decode("ascii")
            key = derive_key(password, salt, kdf)
            decrypt_bytes(key, nonce, canary, b"vault-canary-v1")
        except (UnicodeDecodeError, ValueError, AuthenticationError) as exc:
            raise AuthenticationError("Vault metadata is invalid or authentication failed") from exc
        return key

    def add(self, key: bytes, service: str, username: str, secret: str):
        _validate_identifier(service, "Service")
        _validate_identifier(username, "Username")
        if not isinstance(secret, str): raise TypeError("Secret must be a string")
        nonce, ciphertext = encrypt_bytes(key, secret.encode("utf-8"), _aad(service, username, CURRENT_AAD_VERSION))
        self.db.upsert_credential(service, username, nonce, ciphertext, CURRENT_AAD_VERSION)

    def get(self, key: bytes, service: str, username: str | None = None) -> str:
        row = self.db.get_credential(service, username)
        if row is None: raise KeyError("Credential not found")
        try:
            plaintext = decrypt_bytes(key, row["nonce"], row["ciphertext"], _aad(row["service"], row["username"], row["aad_version"]))
            return plaintext.decode("utf-8")
        except (UnicodeDecodeError, ValueError, InvalidVaultError) as exc:
            raise AuthenticationError("Credential data is invalid or authentication failed") from exc

    def change_master_password(self, current_password: str, new_password: str) -> None:
        old_key = self.unlock(current_password)
        salt = new_salt()
        new_key = derive_key(new_password, salt)
        rows = self.db.conn.execute("SELECT * FROM credentials ORDER BY id").fetchall()
        replacements = []
        for row in rows:
            plaintext = decrypt_bytes(old_key, row["nonce"], row["ciphertext"], _aad(row["service"], row["username"], row["aad_version"]))
            nonce, ciphertext = encrypt_bytes(new_key, plaintext, _aad(row["service"], row["username"], CURRENT_AAD_VERSION))
            replacements.append((nonce, ciphertext, CURRENT_AAD_VERSION, row["id"]))
        canary_nonce, canary = encrypt_bytes(new_key, CANARY, b"vault-canary-v1")
        with self.db.transaction():
            self.db.conn.executemany("UPDATE credentials SET nonce=?, ciphertext=?, aad_version=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", replacements)
            self.db.conn.executemany("INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", {
                "salt": salt, "canary_nonce": canary_nonce, "canary": canary, "kdf": b"argon2id"
            }.items())
