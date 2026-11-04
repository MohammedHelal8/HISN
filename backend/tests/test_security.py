
from app.core.security import (
    hash_password,
    verify_password,
)


def test_password_hashing():
    password = "HISN-Test-Password-2026!"

    hashed = hash_password(password)

    assert hashed != password
    assert hashed.startswith("$argon2id$")


def test_correct_password():
    password = "HISN-Test-Password-2026!"
    hashed = hash_password(password)

    assert verify_password(password, hashed) is True


def test_wrong_password():
    hashed = hash_password("Correct-Password-2026!")

    assert verify_password(
        "Wrong-Password",
        hashed,
    ) is False


def test_invalid_password_hash():
    assert verify_password(
        "Test-Password",
        "invalid-hash",
    ) is False
