
from datetime import datetime, timedelta, timezone

import jwt
from jwt import InvalidTokenError

from app.core.config import settings


ALGORITHM = "HS256"
ISSUER = "hisn"


def create_access_token(admin_id: int) -> str:
    if admin_id <= 0:
        raise ValueError("Invalid administrator ID")

    if settings.jwt_algorithm != ALGORITHM:
        raise ValueError("Unsupported JWT algorithm")

    if settings.jwt_access_token_expire_minutes <= 0:
        raise ValueError("Invalid token expiration")

    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(admin_id),
        "iss": ISSUER,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(
            minutes=settings.jwt_access_token_expire_minutes
        ),
        "type": "access",
    }

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=ALGORITHM,
    )


def verify_access_token(token: str) -> int | None:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={
                "require": [
                    "sub",
                    "iss",
                    "iat",
                    "nbf",
                    "exp",
                    "type",
                ]
            },
        )

        if payload.get("type") != "access":
            return None

        subject = payload.get("sub")

        if not isinstance(subject, str):
            return None

        if not subject.isascii() or not subject.isdecimal():
            return None

        admin_id = int(subject)

        if admin_id <= 0:
            return None

        return admin_id

    except (InvalidTokenError, ValueError, TypeError):
        return None
