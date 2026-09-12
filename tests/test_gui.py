import string

from crypto_vault.gui.password_generator import (
    calculate_entropy,
    generate_password,
    get_strength_info,
)


def test_password_generator_length():
    pwd = generate_password(length=24)
    assert len(pwd) == 24


def test_password_generator_character_sets():
    pwd = generate_password(length=30, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
    assert any(c in string.ascii_uppercase for c in pwd)
    assert any(c in string.ascii_lowercase for c in pwd)
    assert any(c in string.digits for c in pwd)


def test_entropy_and_strength():
    assert calculate_entropy("") == 0.0
    label, _color, _pct = get_strength_info("weak")
    assert label == "Very Weak"

    label_strong, _color_strong, pct_strong = get_strength_info("A!9xK#mP$2026_Secur3KeyVault!")
    assert "Strong" in label_strong
    assert pct_strong >= 85.0
