from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pyperclip
import typer
from rich.console import Console
from rich.table import Table

from crypto_vault.crypto.cipher import decrypt_file, encrypt_file
from crypto_vault.crypto.integrity import create_signature, verify_signature
from crypto_vault.exceptions import CryptoVaultError
from crypto_vault.vault import Vault

app = typer.Typer(help="Secure local password vault and file authenticator.")
vault_app = typer.Typer(help="Password vault operations.")
file_app = typer.Typer(help="File encryption and integrity operations.")
app.add_typer(vault_app, name="vault"); app.add_typer(file_app, name="file")
console = Console()
DEFAULT_DB = Path(os.environ.get("CRYPTOVAULT_DB", "vault.db"))

def password(prompt="Master password"): return typer.prompt(prompt, hide_input=True)
def fail(exc): console.print(f"[red]Error:[/red] {exc}"); raise typer.Exit(1)

@vault_app.command("init")
def vault_init(db: Path = typer.Option(DEFAULT_DB)):
    try:
        first=password("Create master password"); second=password("Confirm master password")
        if first != second: raise ValueError("Passwords do not match")
        with Vault(db) as vault: vault.initialize(first)
        console.print("[green]Vault initialized.[/green]")
    except (CryptoVaultError, OSError, sqlite3.Error, ValueError) as exc: fail(exc)

@vault_app.command("add")
def vault_add(service: str = typer.Option(...), username: str = typer.Option(...), db: Path = typer.Option(DEFAULT_DB)):
    try:
        with Vault(db) as vault:
            key=vault.unlock(password()); secret=typer.prompt("Secret", hide_input=True); vault.add(key, service, username, secret)
        console.print("[green]Credential saved.[/green]")
    except (CryptoVaultError, ValueError) as exc: fail(exc)

@vault_app.command("list")
def vault_list(db: Path = typer.Option(DEFAULT_DB)):
    try:
        with Vault(db) as vault:
            vault.unlock(password())
            rows=vault.db.list_credentials()
        table=Table("Service", "Username", "Created", "Updated")
        for r in rows: table.add_row(r["service"], r["username"], r["created_at"], r["updated_at"])
        console.print(table)
    except (CryptoVaultError, OSError, sqlite3.Error, ValueError) as exc: fail(exc)

@vault_app.command("get")
def vault_get(service: str = typer.Option(...), username: str | None = typer.Option(None), show: bool = False, copy: bool = False, db: Path = typer.Option(DEFAULT_DB)):
    if not show and not copy: fail(ValueError("Choose --show or --copy"))
    try:
        with Vault(db) as vault: secret=vault.get(vault.unlock(password()), service, username)
        if copy:
            pyperclip.copy(secret); console.print("[green]Copied to clipboard.[/green]")
        if show: console.print(secret)
    except (CryptoVaultError, ValueError, KeyError) as exc: fail(exc)

@vault_app.command("delete")
def vault_delete(service: str = typer.Option(...), username: str | None = typer.Option(None), db: Path = typer.Option(DEFAULT_DB)):
    try:
        with Vault(db) as vault:
            vault.unlock(password()); count=vault.db.delete_credential(service, username)
        console.print(f"Deleted {count} credential(s).")
    except (CryptoVaultError, ValueError) as exc: fail(exc)

@vault_app.command("change-master-password")
def vault_change_master_password(db: Path = typer.Option(DEFAULT_DB)):
    try:
        current = password("Current master password")
        first = password("New master password")
        second = password("Confirm new master password")
        if first != second: raise ValueError("Passwords do not match")
        with Vault(db) as vault: vault.change_master_password(current, first)
        console.print("[green]Master password changed.[/green]")
    except (CryptoVaultError, OSError, sqlite3.Error, ValueError) as exc: fail(exc)

@file_app.command("encrypt")
def file_encrypt(
    source: Path,
    output: Path | None = None,
    force: bool = typer.Option(False, "--force"),
    kdf: str = typer.Option("argon2id", "--kdf", help="Key derivation function: argon2id or pbkdf2-sha256."),
):
    try:
        dest = output or Path(str(source) + ".enc")
        encrypt_file(source, dest, password("Passphrase"), kdf=kdf, overwrite=force)
        console.print(f"[green]Created {dest}[/green]")
    except (OSError, CryptoVaultError, ValueError) as exc: fail(exc)

@file_app.command("decrypt")
def file_decrypt(source: Path, output: Path | None = None, force: bool = typer.Option(False, "--force")):
    try:
        dest = decrypt_file(source, output, password("Passphrase"), overwrite=force)
        console.print(f"[green]Created {dest}[/green]")
    except (OSError, CryptoVaultError, ValueError) as exc: fail(exc)

@file_app.command("sign")
def file_sign(source: Path, signature: Path | None = None, force: bool = typer.Option(False, "--force")):
    try:
        dest=signature or Path(str(source)+".sig"); create_signature(source, dest, password("HMAC passphrase"), overwrite=force); console.print(f"[green]Created {dest}[/green]")
    except (CryptoVaultError, OSError, ValueError) as exc: fail(exc)

@file_app.command("verify")
def file_verify(source: Path, signature: Path | None = None):
    sig=signature or Path(str(source)+".sig")
    if verify_signature(source, sig, password("HMAC passphrase")): console.print("[green]Integrity verified.[/green]")
    else: console.print("[red]Verification failed.[/red]"); raise typer.Exit(1)

if __name__ == "__main__": app()
