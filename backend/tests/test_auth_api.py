
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.auth import router
from app.core.database import get_db


def fake_db():
    yield object()


app = FastAPI()
app.include_router(router, prefix="/api")
app.dependency_overrides[get_db] = fake_db

client = TestClient(app)


def test_login_success():
    fake_admin = SimpleNamespace(admin_id=1)

    with patch("app.api.auth.authenticate_admin", return_value=fake_admin), \
         patch("app.api.auth.create_session", return_value=("opaque-session", "csrf-protection")):
        response = client.post(
            "/api/auth/login",
            json={
                "username": "test_admin",
                "password": "Test-Password-2026!",
            },
        )

    assert response.status_code == 200

    data = response.json()

    assert data == {"ok": True}
    assert "hisn_session=" in response.headers["set-cookie"]


def test_login_wrong_credentials():
    with patch(
        "app.api.auth.authenticate_admin",
        return_value=None,
    ):
        response = client.post(
            "/api/auth/login",
            json={
                "username": "test_admin",
                "password": "Wrong-Password",
            },
        )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid username or password"
    )


def test_login_missing_password():
    response = client.post(
        "/api/auth/login",
        json={
            "username": "test_admin",
        },
    )

    assert response.status_code == 422


def test_login_empty_username():
    response = client.post(
        "/api/auth/login",
        json={
            "username": "",
            "password": "Test-Password-2026!",
        },
    )

    assert response.status_code == 422
