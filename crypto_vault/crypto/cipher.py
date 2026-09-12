"""AES-256-GCM helpers and the compact encrypted-file format."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_vault.crypto.kdf import derive_key, new_salt
from crypto_vault.exceptions import AuthenticationError

NONCE_SIZE = 12
SALT_SIZE = 16
TAG_SIZE = 16
MIN_ENCRYPTED_SIZE = SALT_SIZE + NONCE_SIZE + TAG_SIZE

def _write_atomic(destination: Path, data: bytes) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

def _validate_destination(destination: Path, overwrite: bool) -> None:
    if destination.is_symlink():
        raise ValueError("Destination must not be a symbolic link")
    if destination.exists() and not overwrite:
        raise FileExistsError(destination)

def encrypt_bytes(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = os.urandom(NONCE_SIZE)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)

def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    if len(key) != 32 or len(nonce) != NONCE_SIZE:
        raise ValueError("Invalid key or nonce size")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise AuthenticationError("Authentication failed: wrong secret or modified data") from exc

import struct

V2_FILE_MAGIC = b"CVF2\x00"
V3_FILE_MAGIC = b"CVF3\x00"
KDF_IDS = {"argon2id": 1, "pbkdf2-sha256": 2}
KDF_NAMES = {value: key for key, value in KDF_IDS.items()}
V3_PREFIX_SIZE = len(V3_FILE_MAGIC) + 1


def encrypt_file(
    source: Path,
    destination: Path,
    passphrase: str,
    kdf: str = "argon2id",
    overwrite: bool = False,
    version: int = 3,
) -> Path:
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination must differ")
    _validate_destination(destination, overwrite)
    if kdf not in KDF_IDS:
        raise ValueError(f"Unsupported KDF: {kdf}")
    if version not in {1, 2, 3}:
        raise ValueError("Unsupported encrypted-file format version")

    salt = new_salt()
    key = derive_key(passphrase, salt, kdf)
    raw_bytes = source.read_bytes()

    if version == 3:
        # The KDF identifier is public so the correct KDF can be selected before
        # decryption. It is authenticated as AAD, while the original filename
        # remains encrypted to avoid leaking it.
        aad = V3_FILE_MAGIC + bytes([KDF_IDS[kdf]])
        ext_bytes = source.suffix.encode("utf-8")
        name_bytes = source.name.encode("utf-8")
        if len(ext_bytes) > 0xFF or len(name_bytes) > 0xFFFF:
            raise ValueError("Source filename is too long for the encrypted-file format")
        plaintext = struct.pack(">BH", len(ext_bytes), len(name_bytes)) + ext_bytes + name_bytes + raw_bytes
        nonce, ciphertext = encrypt_bytes(key, plaintext, aad)
        payload = V3_FILE_MAGIC + bytes([KDF_IDS[kdf]]) + salt + nonce + ciphertext
    elif version == 2:
        ext_bytes = source.suffix.encode("utf-8")
        name_bytes = source.name.encode("utf-8")
        if len(ext_bytes) > 0xFF or len(name_bytes) > 0xFFFF:
            raise ValueError("Source filename is too long for the encrypted-file format")
        header = V2_FILE_MAGIC + struct.pack(">BH", len(ext_bytes), len(name_bytes)) + ext_bytes + name_bytes
        nonce, ciphertext = encrypt_bytes(key, header + raw_bytes)
        payload = salt + nonce + ciphertext
    else:
        nonce, ciphertext = encrypt_bytes(key, raw_bytes)
        payload = salt + nonce + ciphertext

    _write_atomic(destination, payload)
    return destination


def _decode_v3_payload(payload: bytes, passphrase: str) -> tuple[bytes, str]:
    if len(payload) < V3_PREFIX_SIZE + SALT_SIZE + NONCE_SIZE + TAG_SIZE:
        raise AuthenticationError("Encrypted file is too short")
    kdf_id = payload[len(V3_FILE_MAGIC)]
    kdf = KDF_NAMES.get(kdf_id)
    if payload[:len(V3_FILE_MAGIC)] != V3_FILE_MAGIC or kdf is None:
        raise AuthenticationError("Unsupported encrypted-file format")
    offset = V3_PREFIX_SIZE
    salt = payload[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = payload[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    aad = V3_FILE_MAGIC + bytes([kdf_id])
    plaintext = decrypt_bytes(derive_key(passphrase, salt, kdf), nonce, payload[offset:], aad)
    if len(plaintext) < 3:
        raise AuthenticationError("Invalid encrypted-file metadata")
    ext_len, name_len = struct.unpack(">BH", plaintext[:3])
    header_len = 3 + ext_len + name_len
    if len(plaintext) < header_len:
        raise AuthenticationError("Invalid encrypted-file metadata")
    try:
        ext = plaintext[3:3 + ext_len].decode("utf-8")
        name = plaintext[3 + ext_len:header_len].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuthenticationError("Invalid encrypted-file metadata") from exc
    return plaintext[header_len:], name or (f"restored{ext}" if ext else "decrypted.dec")


def decrypt_file(
    source: Path,
    destination: Path | None = None,
    passphrase: str = "",
    kdf: str = "argon2id",
    overwrite: bool = False,
) -> Path:
    source = Path(source)
    payload = source.read_bytes()
    if len(payload) < MIN_ENCRYPTED_SIZE:
        raise AuthenticationError("Encrypted file is too short")

    if payload.startswith(V3_FILE_MAGIC):
        file_bytes, orig_name = _decode_v3_payload(payload, passphrase)
        orig_ext = Path(orig_name).suffix
    else:
        salt, nonce, ciphertext = payload[:16], payload[16:28], payload[28:]
        plaintext = decrypt_bytes(derive_key(passphrase, salt, kdf), nonce, ciphertext)

        orig_ext = ""
        orig_name = ""
        file_bytes = plaintext

        if len(plaintext) >= 8 and plaintext[:5] == V2_FILE_MAGIC:
            ext_len, name_len = struct.unpack(">BH", plaintext[5:8])
            header_len = 8 + ext_len + name_len
            if len(plaintext) >= header_len:
                try:
                    orig_ext = plaintext[8 : 8 + ext_len].decode("utf-8")
                    orig_name = plaintext[8 + ext_len : header_len].decode("utf-8")
                    file_bytes = plaintext[header_len:]
                except UnicodeDecodeError:
                    pass

    if destination is None:
        if orig_name:
            destination = source.parent / orig_name
        elif orig_ext:
            stem = source.stem if source.suffix == ".enc" else source.name
            destination = source.parent / (stem + orig_ext)
        else:
            destination = source.parent / (source.stem if source.suffix == ".enc" else source.name + ".dec")
    else:
        destination = Path(destination)
        if destination.is_dir():
            if orig_name:
                destination = destination / orig_name
            elif orig_ext:
                stem = source.stem if source.suffix == ".enc" else source.name
                destination = destination / (stem + orig_ext)
            else:
                destination = destination / (source.stem if source.suffix == ".enc" else source.name + ".dec")
        elif orig_ext and (
            destination.suffix == ""
            or destination.suffix.lower() in {".dec", ".enc", ".tmp"}
            or destination.name == source.stem and destination.suffix != orig_ext
        ):
            destination = destination.with_suffix(orig_ext)

    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination must differ")
    _validate_destination(destination, overwrite)
    _write_atomic(destination, file_bytes)
    return destination
