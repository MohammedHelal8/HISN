
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.common import (
    ConfidenceLevel,
    IndicatorType,
    IncidentStatus,
    ServiceStatus,
    NormalizedLogEntry,
    DetectionResult,
)


def test_enums():
    assert IndicatorType.DOMAIN.value == "DOMAIN"
    assert ConfidenceLevel.HIGH.value == "HIGH"
    assert IncidentStatus.NEW.value == "new"
    assert ServiceStatus.UNKNOWN.value == "unknown"


def test_normalized_log_entry():
    entry = NormalizedLogEntry(
        source="e2guardian",
        activity_at=datetime.now(timezone.utc),
        client_ip="192.168.1.10",
        destination="example.com",
        filtering_decision="blocked",
        file_identity="test-log-001",
        line_offset=100,
    )

    assert str(entry.client_ip) == "192.168.1.10"
    assert entry.destination == "example.com"


def test_invalid_offset():
    with pytest.raises(ValidationError):
        NormalizedLogEntry(
            source="e2guardian",
            file_identity="test-log-001",
            line_offset=-1,
        )


def test_detection_result():
    result = DetectionResult(
        detected=True,
        detection_rule="ioc_match",
        indicator_id=1,
        evidence={"destination": "example.com"},
    )

    assert result.detected is True
    assert result.detection_rule == "ioc_match"
