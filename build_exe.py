"""Build script to compile CryptoVault into a standalone Windows .exe file using PyInstaller."""
import sys
from pathlib import Path

import PyInstaller.__main__


def build():
    root = Path(__file__).resolve().parent
    entry_point = root / "main_gui.py"
    dist_dir = root / "dist"
    build_dir = root / "build"

    print(f"Building CryptoVault.exe from {entry_point}...")

    args = [
        str(entry_point),
        "--name=CryptoVault",
        "--onefile",
        "--windowed",
        "--clean",
        f"--distpath={dist_dir}",
        f"--workpath={build_dir}",
        "--hidden-import=crypto_vault",
        "--hidden-import=crypto_vault.crypto",
        "--hidden-import=crypto_vault.crypto.cipher",
        "--hidden-import=crypto_vault.crypto.integrity",
        "--hidden-import=crypto_vault.crypto.kdf",
        "--hidden-import=crypto_vault.db",
        "--hidden-import=crypto_vault.db.database",
        "--hidden-import=crypto_vault.gui",
        "--hidden-import=crypto_vault.gui.app",
        "--hidden-import=crypto_vault.gui.password_generator",
        "--hidden-import=crypto_vault.cli",
        "--hidden-import=crypto_vault.cli.main",
        "--hidden-import=argon2",
        "--hidden-import=argon2.low_level",
        "--hidden-import=argon2_cffi_bindings",
        "--hidden-import=cryptography",
        "--hidden-import=cryptography.hazmat.primitives.ciphers.aead",
        "--hidden-import=cryptography.hazmat.primitives.kdf.pbkdf2",
        "--hidden-import=sqlite3",
        "--hidden-import=tkinter",
        "--hidden-import=pyperclip",
        "--collect-all=cryptography",
        "--collect-all=argon2",
        "--noconfirm",
    ]

    PyInstaller.__main__.run(args)

    exe_path = dist_dir / "CryptoVault.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print("\n=======================================================")
        print(f"SUCCESS: {exe_path} generated!")
        print(f"Size: {size_mb:.2f} MB")
        print("=======================================================\n")
    else:
        print("ERROR: CryptoVault.exe was not found in dist/")
        sys.exit(1)

if __name__ == "__main__":
    build()
