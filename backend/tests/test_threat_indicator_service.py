
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from sqlalchemy import BigInteger, Integer
from sqlalchemy.ext.compiler import compiles
from app.core.database import Base
from app.models.threat_indicator import ThreatIndicator
from app.schemas.threat_indicator import ThreatIndicatorCreate
from app.services.threat_indicator_service import (
    DuplicateThreatIndicatorError,
    create_threat_indicator,
    get_threat_indicator,
)

@compiles(BigInteger, "sqlite")
def compile_big_integer_sqlite(type_, compiler, **kw):
    return "INTEGER"


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # Create only the threat_indicators table for these tests.
    ThreatIndicator.__table__.create(engine)

    with Session(engine) as session:
        yield session

    engine.dispose()


def sample_indicator():
    return ThreatIndicatorCreate(
        indicator_type="DOMAIN",
        indicator_value="malicious.example",
        source_name="Test Feed",
        confidence_level="HIGH",
    )


def test_create_threat_indicator(db):
    indicator = create_threat_indicator(
        db,
        sample_indicator(),
    )

    assert indicator.indicator_id is not None
    assert indicator.indicator_value == "malicious.example"
    assert indicator.confidence_level == "HIGH"


def test_get_threat_indicator(db):
    create_threat_indicator(db, sample_indicator())

    indicator = get_threat_indicator(
        db,
        indicator_type="DOMAIN",
        indicator_value="malicious.example",
        source_name="Test Feed",
    )

    assert indicator is not None
    assert indicator.source_name == "Test Feed"


def test_duplicate_threat_indicator(db):
    create_threat_indicator(db, sample_indicator())

    with pytest.raises(DuplicateThreatIndicatorError):
        create_threat_indicator(
            db,
            sample_indicator(),
        )


def test_same_indicator_different_source(db):
    create_threat_indicator(db, sample_indicator())

    second = ThreatIndicatorCreate(
        indicator_type="DOMAIN",
        indicator_value="malicious.example",
        source_name="Another Feed",
        confidence_level="MEDIUM",
    )

    indicator = create_threat_indicator(db, second)

    assert indicator.indicator_id is not None
    assert indicator.source_name == "Another Feed"
