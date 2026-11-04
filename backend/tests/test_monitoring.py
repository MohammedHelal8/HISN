
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.core.auth_dependencies import get_current_user
from app.services import monitoring_service


def test_resources_have_real_measurements():
    result = monitoring_service.get_system_resources()

    assert 0 <= result["cpu"]["usage_percent"] <= 100
    assert 0 <= result["memory"]["usage_percent"] <= 100
    assert 0 <= result["disk"]["usage_percent"] <= 100

    assert result["memory"]["total_bytes"] > 0
    assert result["disk"]["total_bytes"] > 0


def test_linux_service_unavailable_on_windows():
    with patch.object(
        monitoring_service.platform,
        "system",
        return_value="Windows",
    ):
        result = monitoring_service.check_linux_service(
            "squid.service"
        )

    assert result["status"] == "unavailable"


def test_hisn_database_failure():
    with patch.object(
        monitoring_service,
        "check_database_connection",
        side_effect=RuntimeError("Database unavailable"),
    ):
        result = monitoring_service.get_hisn_status()

    assert result["status"] == "degraded"
    assert result["database"] == "unavailable"


def test_monitoring_requires_authentication():
    with TestClient(app) as client:
        response = client.get("/api/monitoring/overview")

    assert response.status_code == 401


def test_viewer_can_read_monitoring():
    app.dependency_overrides[get_current_user] = lambda: (
        SimpleNamespace(
            admin_id=2,
            username="viewer",
            role="viewer",
            is_active=True,
        )
    )

    try:
        with patch(
            "app.api.monitoring.get_monitoring_overview",
            return_value={"systems": {}, "resources": {}},
        ):
            with TestClient(app) as client:
                response = client.get(
                    "/api/monitoring/overview"
                )

        assert response.status_code == 200
        assert "systems" in response.json()

    finally:
        app.dependency_overrides.pop(
            get_current_user,
            None,
        )
