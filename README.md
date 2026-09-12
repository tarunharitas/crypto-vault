# CryptoVault

A modular Python CLI for a local encrypted credential vault, authenticated file encryption, and keyed file-integrity checks.

> **Security status:** This is a security-focused portfolio project, not an independently audited password manager. Do not describe it as audited or compliance-ready. Back up encrypted data, use a strong unique master passphrase, and test recovery before relying on it.

## Features

- **Version 3.0**: Authenticated self-describing file container (`CVF3\x00`). Records and authenticates KDF identifier (Argon2id or PBKDF2-SHA256) as AES-GCM AAD while encrypting the original filename and file extension (`.png`, `.pdf`, `.docx`, etc.).
- Full backward-compatibility: Seamlessly decrypts legacy V1, V2, and modern V3 encrypted containers.
- Argon2id key derivation using 64 MiB, 3 iterations, and parallelism 4
- Explicit PBKDF2-HMAC-SHA256 fallback implementation with 600,000 iterations
- AES-256-GCM with fresh 12-byte nonces and authenticated service/username metadata
- Encrypted canary for master-password validation
- SQLite persistence, WAL mode, unique constraints, and parameterized SQL
- File format: V3 `magic (5) | KDF id (1) | salt (16) | nonce (12) | ciphertext+GCM tag`; V1/V2 legacy containers remain supported.
- Streaming 64 KiB HMAC-SHA256 integrity checks with constant-time comparison
- Modern Desktop GUI application + Standalone 64-bit Windows `.exe` binary
- Comprehensive security audit documentation (`SECURITY.md` and `SECURITY_AUDIT.md`)
- Typer and Rich CLI, tests, packaging, MIT license, and GitHub Actions CI

## Running the Windows Executable (`CryptoVault.exe`)

When running `CryptoVault.exe` downloaded from GitHub or the web on Windows 10/11, Windows SmartScreen / Smart App Control may display an unknown publisher prompt (standard for open-source binaries distributed without an enterprise code-signing certificate).

### How to Run:
1. **Unblock via File Properties (Recommended & Permanent)**:
   - Right-click `CryptoVault.exe` &rarr; **Properties**.
   - In the **General** tab under the **Security** section at the bottom, check **☑️ Unblock**.
   - Click **Apply** and **OK**. The application will now launch cleanly on double-click with Smart Control remaining active.
2. **From the SmartScreen Prompt**:
   - Click **"More info"**.
   - Click **"Run anyway"**.
3. **Via PowerShell**:
   ```powershell
   Unblock-File -Path .\CryptoVault.exe
   .\CryptoVault.exe
   ```

## Threat model and limitations

CryptoVault protects secrets at rest if an attacker obtains only the database or encrypted file and does not know the passphrase. AES-GCM detects modified ciphertext, tags, and AAD. It does not protect an unlocked machine, malware, keyloggers, process-memory inspection, weak passphrases, clipboard monitoring, deletion, rollback to an older valid database, or loss of the only database copy. Python cannot reliably guarantee that secret bytes are erased from process memory.

The HMAC command is a **message authentication code**, not a public-key digital signature. Anyone who knows its passphrase can create a valid `.sig` manifest. The web demo is educational only; never enter real credentials or production secrets into the public GitHub Pages demo.

Encrypted files now use a versioned V3 container by default. V3 stores a small public format/KDF identifier and authenticates it as AES-GCM associated data, while the original filename remains encrypted. V1 and V2 containers remain readable for backward compatibility. V2 has no embedded KDF identifier, so legacy PBKDF2 files must be decrypted with the matching `kdf` argument in the Python API. File encryption currently reads the entire file into memory; HMAC processing is streaming. New vault credentials use unambiguous length-prefixed AAD; existing credentials retain their legacy AAD version and remain readable.

File and signature outputs are written through temporary files and atomically replaced. Existing outputs, destination symbolic links, and source/destination collisions are rejected unless `--force` is supplied for a distinct destination. SQLite metadata, usernames, timestamps, WAL files, and deleted-record remnants may still be visible to a local filesystem observer; this tool does not provide secure file erasure.

## Install

### Option A: Windows Package Manager (`winget`) — Recommended

Install CryptoVault directly on any Windows 10/11 PC with zero SmartScreen friction:

```powershell
winget install tarunharitas.CryptoVault
```

> **Manifest Status**: Pre-configured and validated winget manifests are located in [`winget/manifests/t/tarunharitas/CryptoVault/3.0.0/`](./winget/manifests/t/tarunharitas/CryptoVault/3.0.0/). Validated against Microsoft's schema via `winget validate`.

### Option B: Standalone Windows Executable (`.exe`)

Download `CryptoVault.exe` directly from the [Showcase Website](https://tarunharitas.github.io/crypto-vault/) or [GitHub Releases](https://github.com/tarunharitas/crypto-vault/releases).

### Option C: From Source (Python Developer Setup)

```bash
git clone https://github.com/tarunharitas/crypto-vault.git
cd crypto-vault
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e .[dev]
```

macOS/Linux:

```bash
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[dev]'
```

## CLI

```bash
cryptovault --help
cryptovault vault init
cryptovault vault add --service github --username developer@example.com
cryptovault vault list
cryptovault vault get --service github --username developer@example.com --show
cryptovault vault get --service github --username developer@example.com --copy
cryptovault vault delete --service github --username developer@example.com
cryptovault vault change-master-password

cryptovault file encrypt secret_document.pdf
cryptovault file encrypt secret_document.pdf --kdf pbkdf2-sha256
cryptovault file decrypt secret_document.pdf.enc
cryptovault file sign backup.tar.gz
cryptovault file verify backup.tar.gz
```

File commands refuse to replace an existing destination by default. Use `--force`
only when replacement is intentional:

```bash
cryptovault file encrypt secret_document.pdf --force
cryptovault file decrypt secret_document.pdf.enc --force
cryptovault file sign backup.tar.gz --force
```

`vault list` requires the master password because service names and usernames are
stored as database metadata. Password rotation re-encrypts every credential and
replaces the encrypted canary in one database transaction.

The database defaults to `vault.db`. Set `CRYPTOVAULT_DB` or pass `--db` to use another path. Database and generated secret artifacts are excluded by `.gitignore`. Never commit real passwords, vault databases, encrypted personal files, passphrases, or API keys.

## Tests

```bash
python -m pytest --cov=crypto_vault --cov-report=term-missing
python -m ruff check .
```

Tests cover KDF determinism, salt/nonce uniqueness, AEAD round trips, AAD and ciphertext tampering, the 28-byte file header, HMAC verification, parameterized database operations, and CLI startup.



## Modern Desktop GUI & Windows Executable

CryptoVault includes a dark-themed desktop application with a cyberpunk/fintech aesthetic:

- **Launch GUI directly with Python**:
  ```powershell
  python main_gui.py
  ```
- **Run Standalone Windows Executable**:
  Double-click `CryptoVault.exe` (or `dist\CryptoVault.exe`). It runs directly on Windows 64-bit without requiring Python or external dependencies.
- **Rebuild Executable**:
  ```powershell
  python build_exe.py
  ```

## License

MIT
