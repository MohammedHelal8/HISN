
import pytest
from pydantic import ValidationError

from app.schemas.threat_indicator import ThreatIndicatorCreate


def test_valid_domain_indicator():
    indicator = ThreatIndicatorCreate(
        indicator_type="DOMAIN",
        indicator_value="  Example.COM  ",
        source_name="Test Feed",
        confidence_level="HIGH",
    )

    assert indicator.indicator_value == "example.com"


def test_valid_ip_indicator():
    indicator = ThreatIndicatorCreate(
        indicator_type="IP",
        indicator_value="192.168.1.10",
        source_name="Test Feed",
        confidence_level="MEDIUM",
    )

    assert indicator.indicator_value == "192.168.1.10"


def test_invalid_ip_indicator():
    with pytest.raises(ValidationError):
        ThreatIndicatorCreate(
            indicator_type="IP",
            indicator_value="999.999.999.999",
            source_name="Test Feed",
            confidence_level="HIGH",
        )


def test_invalid_confidence_level():
    with pytest.raises(ValidationError):
        ThreatIndicatorCreate(
            indicator_type="DOMAIN",
            indicator_value="example.com",
            source_name="Test Feed",
            confidence_level="CRITICAL",
        )


def test_empty_indicator_value():
    with pytest.raises(ValidationError):
        ThreatIndicatorCreate(
            indicator_type="DOMAIN",
            indicator_value="   ",
            source_name="Test Feed",
            confidence_level="LOW",
        )



@pytest.mark.parametrize(
    "domain, expected",
    [
        ("example.com", "example.com"),
        ("sub.example.com", "sub.example.com"),
        ("EXAMPLE.COM", "example.com"),
    ],
)
def test_valid_domain_formats(domain, expected):
    indicator = ThreatIndicatorCreate(
        indicator_type="DOMAIN",
        indicator_value=domain,
        source_name="Manual",
        confidence_level="HIGH",
    )

    assert indicator.indicator_value == expected


@pytest.mark.parametrize(
    "domain",
    [
        "not a valid domain!",
        "invalid_domain.com",
        "-example.com",
        "example-.com",
        "example..com",
        "example",
        ".example.com",
    ],
)
def test_invalid_domain_formats(domain):
    with pytest.raises(ValidationError):
        ThreatIndicatorCreate(
            indicator_type="DOMAIN",
            indicator_value=domain,
            source_name="Manual",
            confidence_level="HIGH",
        )
