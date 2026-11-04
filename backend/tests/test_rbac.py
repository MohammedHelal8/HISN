
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.main import app
from app.core.database import get_db
from unittest.mock import patch
from app.core.session_auth import COOKIE_NAME


class FakeDB:
    def __init__(self, role):
        self.role = role

    def get(self, model, user_id):
        return SimpleNamespace(
            admin_id=user_id,
            username=self.role,
            is_active=True,
            role=self.role,
        )


def test_viewer_cannot_access_threat_indicators():
    def override_get_db():
        yield FakeDB("viewer")

    app.dependency_overrides[get_db] = override_get_db

    try:
        with patch("app.core.auth_dependencies.lookup_session", return_value=SimpleNamespace(user_id=2)):
            with TestClient(app) as client:
                response = client.get("/api/threat-indicators", cookies={COOKIE_NAME: "test-session"})

        assert response.status_code == 403

    finally:
        app.dependency_overrides.pop(get_db, None)


def test_viewer_can_access_own_profile():
    def override_get_db():
        yield FakeDB("viewer")

    app.dependency_overrides[get_db] = override_get_db

    try:
        with patch("app.core.auth_dependencies.lookup_session", return_value=SimpleNamespace(user_id=2)):
            with TestClient(app) as client:
                response = client.get("/api/users/me", cookies={COOKIE_NAME: "test-session"})

        assert response.status_code == 200
        assert response.json()["role"] == "viewer"

    finally:
        app.dependency_overrides.pop(get_db, None)
