
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.main import app
from app.core.database import get_db
from app.core.auth_dependencies import get_current_admin
from app.services.threat_indicator_service import (
    DuplicateThreatIndicatorError,
)


def test_create_threat_indicator_success():
    fake_db = Mock()

    fake_admin = SimpleNamespace(
        admin_id=1,
        username="test_admin",
        is_active=True,
    )

    def override_get_db():
        yield fake_db

    def override_get_current_admin():
        return fake_admin

    now = datetime.now(timezone.utc)

    fake_indicator = SimpleNamespace(
        indicator_id=1,
        indicator_type="DOMAIN",
        indicator_value="malicious-example.test",
        source_name="Manual",
        confidence_level="HIGH",
        first_seen_at=now,
        last_updated_at=now,
        expires_at=None,
        is_active=True,
    )

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_admin] = (
        override_get_current_admin
    )

    try:
        with patch(
            "app.api.threat_indicators.create_threat_indicator",
            return_value=fake_indicator,
        ) as mock_create:

            client = TestClient(app)

            response = client.post(
                "/api/threat-indicators",
                json={
                    "indicator_type": "DOMAIN",
                    "indicator_value": "malicious-example.test",
                    "source_name": "Manual",
                    "confidence_level": "HIGH",
                },
            )

            assert response.status_code == 201

            result = response.json()

            assert result["indicator_id"] == 1
            assert result["indicator_type"] == "DOMAIN"
            assert result["indicator_value"] == (
                "malicious-example.test"
            )
            assert result["confidence_level"] == "HIGH"
            assert result["is_active"] is True

            mock_create.assert_called_once()

            args, kwargs = mock_create.call_args

            assert args[0] is fake_db
            assert args[1].indicator_value == (
                "malicious-example.test"
            )

    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_admin, None)


def test_create_duplicate_threat_indicator():
    fake_db = Mock()

    fake_admin = SimpleNamespace(
        admin_id=1,
        username="test_admin",
        is_active=True,
    )

    def override_get_db():
        yield fake_db

    def override_get_current_admin():
        return fake_admin

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_admin] = (
        override_get_current_admin
    )

    try:
        with patch(
            "app.api.threat_indicators.create_threat_indicator",
            side_effect=DuplicateThreatIndicatorError(
                "Threat indicator already exists"
            ),
        ) as mock_create:

            client = TestClient(app)

            response = client.post(
                "/api/threat-indicators",
                json={
                    "indicator_type": "DOMAIN",
                    "indicator_value": "malicious-example.test",
                    "source_name": "Manual",
                    "confidence_level": "HIGH",
                },
            )

            assert response.status_code == 409
            assert response.json() == {
                "detail": "Threat indicator already exists"
            }

            mock_create.assert_called_once()

    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_admin, None)

def test_create_threat_indicator_invalid_ip():
    fake_db = Mock()

    fake_admin = SimpleNamespace(
        admin_id=1,
        username="test_admin",
        is_active=True,
    )

    def override_get_db():
        yield fake_db

    def override_get_current_admin():
        return fake_admin

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_admin] = (
        override_get_current_admin
    )

    try:
        with patch(
            "app.api.threat_indicators.create_threat_indicator"
        ) as mock_create:

            client = TestClient(app)

            response = client.post(
                "/api/threat-indicators",
                json={
                    "indicator_type": "IP",
                    "indicator_value": "999.999.999.999",
                    "source_name": "Manual",
                    "confidence_level": "HIGH",
                },
            )

            assert response.status_code == 422

            mock_create.assert_not_called()

    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_admin, None)

