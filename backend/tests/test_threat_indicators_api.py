
from types import SimpleNamespace
from unittest.mock import Mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.threat_indicators import router
from app.core.database import get_db
from unittest.mock import patch
from app.core.session_auth import COOKIE_NAME


app = FastAPI()
app.include_router(router, prefix="/api")

fake_db = Mock()


def override_db():
    yield fake_db


app.dependency_overrides[get_db] = override_db

client = TestClient(app)


def test_missing_token():
    response = client.get("/api/threat-indicators")

    assert response.status_code == 401


def test_invalid_token():
    response = client.get(
        "/api/threat-indicators",
        headers={
            "Authorization": "Bearer invalid-token"
        },
    )

    assert response.status_code == 401


def test_valid_token_active_admin():
    fake_db.reset_mock(
        return_value=True,
        side_effect=True,
    )

    def fake_get(model, admin_id):
        return SimpleNamespace(
            admin_id=admin_id,
            is_active=True,
	    role="admin",
        )

    fake_db.get.side_effect = fake_get
    fake_db.scalars.return_value.all.return_value = []

    with patch("app.core.auth_dependencies.lookup_session", return_value=SimpleNamespace(user_id=1)):
        response = client.get("/api/threat-indicators", cookies={COOKIE_NAME: "test-session"})

    assert response.status_code == 200
    assert response.json() == []
    fake_db.scalars.assert_called_once()


def test_valid_token_inactive_admin():
    fake_db.reset_mock(
        return_value=True,
        side_effect=True,
    )

    fake_db.get.return_value = SimpleNamespace(
        admin_id=1,
        is_active=False,
    )

    with patch("app.core.auth_dependencies.lookup_session", return_value=SimpleNamespace(user_id=1)):
        response = client.get("/api/threat-indicators", cookies={COOKIE_NAME: "test-session"})

    assert response.status_code == 401
    fake_db.scalars.assert_not_called()
