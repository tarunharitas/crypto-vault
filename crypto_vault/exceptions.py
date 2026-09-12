class CryptoVaultError(Exception):
    """Base exception."""

class AuthenticationError(CryptoVaultError):
    """Raised for an incorrect passphrase or authenticated-data tampering."""

class VaultAlreadyInitializedError(CryptoVaultError):
    pass

class VaultNotInitializedError(CryptoVaultError):
    pass

class InvalidVaultError(CryptoVaultError):
    """Raised when vault metadata is missing or malformed."""
