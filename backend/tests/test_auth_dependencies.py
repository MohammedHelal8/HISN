
from types import SimpleNamespace
from unittest.mock import Mock

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.core.auth_dependencies import get_current_admin
from app.core.database import get_db
from unittest.mock import patch
from app.core.session_auth import COOKIE_NAME


app = FastAPI()


@app.get("/protected")
def protected_route(admin=Depends(get_current_admin)):
    return {"admin_id": admin.admin_id}


fake_db = Mock()


def override_db():
    yield fake_db


app.dependency_overrides[get_db] = override_db

client = TestClient(app)


def test_missing_token():
    response = client.get("/protected")

    assert response.status_code == 401


def test_invalid_token():
    response = client.get(
        "/protected",
        headers={
            "Authorization": "Bearer invalid-token"
        },
    )

    assert response.status_code == 401


def test_valid_token_active_admin():
    fake_db.get.return_value = SimpleNamespace(
        admin_id=1,
        is_active=True,
        role="admin",
    )

    with patch("app.core.auth_dependencies.lookup_session", return_value=SimpleNamespace(user_id=1)):
        response = client.get("/protected", cookies={COOKIE_NAME: "test-session"})

    assert response.status_code == 200
    assert response.json() == {"admin_id": 1}


def test_valid_token_inactive_admin():
    fake_db.get.return_value = SimpleNamespace(
        admin_id=1,
        is_active=False,
    )

    with patch("app.core.auth_dependencies.lookup_session", return_value=SimpleNamespace(user_id=1)):
        response = client.get("/protected", cookies={COOKIE_NAME: "test-session"})

    assert response.status_code == 401


def test_valid_token_unknown_admin():
    fake_db.get.return_value = None

    with patch("app.core.auth_dependencies.lookup_session", return_value=SimpleNamespace(user_id=999)):
        response = client.get("/protected", cookies={COOKIE_NAME: "test-session"})

    assert response.status_code == 401
