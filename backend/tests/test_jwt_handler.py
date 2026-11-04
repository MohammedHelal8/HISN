
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.core.config import settings
from app.core.jwt_handler import (
    create_access_token,
    verify_access_token,
)


@pytest.fixture(autouse=True)
def jwt_test_secret(monkeypatch):
    # Legacy JWT serialization tests only; browser auth never accepts JWT.
    monkeypatch.setattr(settings, 'jwt_secret_key', 'unit-test-only-not-for-production')


def test_valid_access_token():
    token = create_access_token(1)

    assert verify_access_token(token) == 1


def test_invalid_admin_id():
    with pytest.raises(ValueError):
        create_access_token(0)


def test_invalid_token():
    assert verify_access_token("invalid.token.value") is None


def test_tampered_token():
    token = create_access_token(1)

    parts = token.split(".")
    parts[2] = "invalidsignature"

    tampered = ".".join(parts)

    assert verify_access_token(tampered) is None


def test_expired_token():
    now = datetime.now(timezone.utc)

    payload = {
        "sub": "1",
        "iss": "hisn",
        "iat": now - timedelta(hours=2),
        "nbf": now - timedelta(hours=2),
        "exp": now - timedelta(hours=1),
        "type": "access",
    }

    token = jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm="HS256",
    )

    assert verify_access_token(token) is None


def test_wrong_token_type():
    now = datetime.now(timezone.utc)

    payload = {
        "sub": "1",
        "iss": "hisn",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=15),
        "type": "refresh",
    }

    token = jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm="HS256",
    )

    assert verify_access_token(token) is None
