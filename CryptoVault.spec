# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = []
binaries = []
hiddenimports = ['crypto_vault', 'crypto_vault.crypto', 'crypto_vault.crypto.cipher', 'crypto_vault.crypto.integrity', 'crypto_vault.crypto.kdf', 'crypto_vault.db', 'crypto_vault.db.database', 'crypto_vault.gui', 'crypto_vault.gui.app', 'crypto_vault.gui.password_generator', 'crypto_vault.cli', 'crypto_vault.cli.main', 'argon2', 'argon2.low_level', 'argon2_cffi_bindings', 'cryptography', 'cryptography.hazmat.primitives.ciphers.aead', 'cryptography.hazmat.primitives.kdf.pbkdf2', 'sqlite3', 'tkinter', 'pyperclip']
tmp_ret = collect_all('cryptography')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('argon2')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['C:/Users/Tarun/Downloads/crypto-vault-main/main_gui.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='CryptoVault',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
