import os

import pytest
from typer.testing import CliRunner

from crypto_vault.cli.main import app
from crypto_vault.crypto.cipher import (
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
)
from crypto_vault.crypto.integrity import create_signature, verify_signature
from crypto_vault.crypto.kdf import derive_argon2id, derive_pbkdf2, new_salt
from crypto_vault.exceptions import AuthenticationError
from crypto_vault.vault import Vault


def test_kdfs_deterministic():
    salt=os.urandom(16)
    assert derive_argon2id("pass",salt)==derive_argon2id("pass",salt)
    assert derive_pbkdf2("pass",salt)==derive_pbkdf2("pass",salt)

def test_salts_unique(): assert new_salt()!=new_salt()
def test_short_salt_rejected():
    with pytest.raises(ValueError): derive_argon2id("pass", b"short")

def test_aead_and_tampering():
    key=os.urandom(32); nonce, ct=encrypt_bytes(key,b"secret",b"aad")
    assert decrypt_bytes(key,nonce,ct,b"aad")==b"secret"
    with pytest.raises(AuthenticationError): decrypt_bytes(key,nonce,ct,b"wrong")
    damaged=ct[:-1]+bytes([ct[-1]^1])
    with pytest.raises(AuthenticationError): decrypt_bytes(key,nonce,damaged,b"aad")

def test_nonce_unique():
    key=os.urandom(32); assert encrypt_bytes(key,b"x")[0] != encrypt_bytes(key,b"x")[0]

def test_file_format_and_tamper(tmp_path):
    src=tmp_path/"a"; enc=tmp_path/"a.enc"; out=tmp_path/"out"; src.write_bytes(b"hello")
    encrypt_file(src,enc,"pass",version=1); assert len(enc.read_bytes())==16+12+5+16
    decrypt_file(enc,out,"pass"); assert out.read_bytes()==b"hello"
    p=bytearray(enc.read_bytes()); p[-1]^=1; enc.write_bytes(p)
    with pytest.raises(AuthenticationError): decrypt_file(enc,out,"pass", overwrite=True)

def test_file_format_v2_preserves_extension(tmp_path):
    # Test 1: .pdf file preservation (v2 container)
    pdf_src = tmp_path / "report.pdf"
    pdf_src.write_bytes(b"%PDF-1.4 test document content")
    pdf_enc = tmp_path / "report.enc"
    encrypt_file(pdf_src, pdf_enc, "master_pass", version=2)
    
    # Simulate original file deleted, decrypt restores report.pdf
    pdf_src.unlink()
    restored_1 = decrypt_file(pdf_enc, passphrase="master_pass")
    assert restored_1.name == "report.pdf"
    assert restored_1.read_bytes() == b"%PDF-1.4 test document content"

    # Test 2: .png file preservation even if output path had no extension (v3 container default)
    png_src = tmp_path / "avatar.png"
    png_src.write_bytes(b"\x89PNG\r\n\x1a\nfake image data")
    png_enc = tmp_path / "avatar_backup.enc"
    encrypt_file(png_src, png_enc, "master_pass")

    # Decrypt specifying output path without extension
    out_target = tmp_path / "restored_image"
    restored_2 = decrypt_file(png_enc, out_target, "master_pass")
    assert restored_2.name == "restored_image.png"
    assert restored_2.read_bytes() == b"\x89PNG\r\n\x1a\nfake image data"

def test_file_format_v3_kdf_selection_and_tampering(tmp_path):
    src = tmp_path / "notes.txt"
    src.write_bytes(b"confidential text")
    enc = tmp_path / "notes.enc"
    encrypt_file(src, enc, "passphrase", kdf="pbkdf2-sha256")
    src.unlink()
    # Decrypt without explicitly providing kdf, V3 header auto-detects
    restored = decrypt_file(enc, passphrase="passphrase")
    assert restored.read_bytes() == b"confidential text"

    # Tampering with KDF byte in header fails AAD authentication
    raw = bytearray(enc.read_bytes())
    raw[5] = 1 if raw[5] == 2 else 2
    enc.write_bytes(raw)
    with pytest.raises(AuthenticationError):
        decrypt_file(enc, passphrase="passphrase", overwrite=True)

def test_hmac(tmp_path):
    src=tmp_path/"data"; sig=tmp_path/"data.sig"; src.write_bytes(b"abc")
    create_signature(src,sig,"pass"); assert verify_signature(src,sig,"pass")
    src.write_bytes(b"abd"); assert not verify_signature(src,sig,"pass")

def test_vault_crud_and_aad(tmp_path):
    db=tmp_path/"vault.db"
    with Vault(db) as v:
        v.initialize("master"); key=v.unlock("master"); v.add(key,"github","dev@example.com","secret")
        assert v.get(key,"github","dev@example.com")=="secret"
        row=v.db.get_credential("github","dev@example.com")
        with pytest.raises(AuthenticationError): decrypt_bytes(key,row["nonce"],row["ciphertext"],b"other:user")
        v.add(key,"x'); DROP TABLE credentials;--","u","s")
        assert len(v.db.list_credentials())==2

def test_vault_aad_is_unambiguous(tmp_path):
    db=tmp_path/"vault.db"
    with Vault(db) as v:
        v.initialize("master"); key=v.unlock("master")
        v.add(key,"a:b","c","first")
        v.add(key,"a","b:c","second")
        assert v.get(key,"a:b","c")=="first"
        assert v.get(key,"a","b:c")=="second"

def test_corrupt_vault_metadata_is_authentication_error(tmp_path):
    db=tmp_path/"vault.db"
    with Vault(db) as v:
        v.initialize("master")
        v.db.set_meta("kdf", b"unknown")
        with pytest.raises(AuthenticationError):
            v.unlock("master")

def test_file_outputs_do_not_overwrite(tmp_path):
    src=tmp_path/"source"; enc=tmp_path/"source.enc"
    src.write_bytes(b"hello"); enc.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        encrypt_file(src,enc,"pass")
    assert enc.read_bytes()==b"existing"

def test_decrypt_rejects_same_source_and_destination(tmp_path):
    src=tmp_path/"source"; enc=tmp_path/"source.enc"
    src.write_bytes(b"hello"); encrypt_file(src,enc,"pass")
    with pytest.raises(ValueError):
        decrypt_file(enc,enc,"pass")

def test_legacy_aad_credentials_remain_readable(tmp_path):
    db=tmp_path/"vault.db"
    with Vault(db) as v:
        v.initialize("master"); key=v.unlock("master")
        nonce, ciphertext=encrypt_bytes(key,b"legacy",b"service:user")
        v.db.upsert_credential("service","user",nonce,ciphertext,1)
        assert v.get(key,"service","user")=="legacy"

def test_change_master_password_reencrypts_credentials(tmp_path):
    db=tmp_path/"vault.db"
    with Vault(db) as v:
        v.initialize("old"); key=v.unlock("old"); v.add(key,"service","user","secret")
        v.change_master_password("old","new")
        with pytest.raises(AuthenticationError): v.unlock("old")
        new_key=v.unlock("new")
        assert v.get(new_key,"service","user")=="secret"

def test_cli_help():
    result=CliRunner().invoke(app,["--help"]); assert result.exit_code==0
