"""Universal Entry Point for CryptoVault Desktop Application and CLI."""
from __future__ import annotations

import sys


def main():
    # If no arguments or explicitly asked for GUI, launch Modern Desktop UI
    cli_commands = {"vault", "file", "--help", "-h", "--version"}
    has_cli_args = len(sys.argv) > 1 and any(arg in cli_commands for arg in sys.argv[1:])

    if not has_cli_args:
        from crypto_vault.gui.app import run_app
        run_app()
    else:
        from crypto_vault.cli.main import app
        app()


if __name__ == "__main__":
    main()
