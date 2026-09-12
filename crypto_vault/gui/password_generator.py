"""Cryptographically secure password generator and entropy scoring."""
from __future__ import annotations

import math
import secrets
import string

UPPERCASE = string.ascii_uppercase
LOWERCASE = string.ascii_lowercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

def generate_password(
    length: int = 18,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """Generate a cryptographically secure random password using secrets module."""
    length = max(length, 4)
    length = min(length, 128)

    chars_pools = []
    guaranteed = []

    if use_upper:
        chars_pools.append(UPPERCASE)
        guaranteed.append(secrets.choice(UPPERCASE))
    if use_lower:
        chars_pools.append(LOWERCASE)
        guaranteed.append(secrets.choice(LOWERCASE))
    if use_digits:
        chars_pools.append(DIGITS)
        guaranteed.append(secrets.choice(DIGITS))
    if use_symbols:
        chars_pools.append(SYMBOLS)
        guaranteed.append(secrets.choice(SYMBOLS))

    if not chars_pools:
        chars_pools = [LOWERCASE + DIGITS]
        guaranteed = [secrets.choice(LOWERCASE), secrets.choice(DIGITS)]

    all_chars = "".join(chars_pools)
    remaining_length = max(0, length - len(guaranteed))
    password_chars = guaranteed + [secrets.choice(all_chars) for _ in range(remaining_length)]

    # Cryptographically shuffle characters
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def calculate_entropy(password: str) -> float:
    """Calculate Shannon-like password entropy in bits."""
    if not password:
        return 0.0

    pool_size = 0
    if any(c in UPPERCASE for c in password):
        pool_size += len(UPPERCASE)
    if any(c in LOWERCASE for c in password):
        pool_size += len(LOWERCASE)
    if any(c in DIGITS for c in password):
        pool_size += len(DIGITS)
    if any(c in SYMBOLS or not c.isalnum() for c in password):
        pool_size += len(SYMBOLS)

    if pool_size == 0:
        pool_size = 1

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 1)


def get_strength_info(password: str) -> tuple[str, str, float]:
    """Return (label, color_hex, percentage 0..100) based on entropy and length."""
    if not password:
        return "Empty", "#64748B", 0.0

    entropy = calculate_entropy(password)

    if entropy < 30 or len(password) < 6:
        return "Very Weak", "#EF4444", 20.0
    if entropy < 50 or len(password) < 8:
        return "Weak", "#F97316", 40.0
    if entropy < 70 or len(password) < 12:
        return "Moderate", "#FBBF24", 65.0
    if entropy < 90:
        return "Strong", "#10B981", 85.0
    return "Very Strong (Armor)", "#06B6D4", 100.0
