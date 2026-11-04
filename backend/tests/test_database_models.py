
import app.models

from sqlalchemy import UniqueConstraint
from app.core.database import Base


EXPECTED_TABLES = {
    "administrators",
    "threat_indicators",
    "security_events",
    "security_incidents",
    "incident_events",
    "blocking_actions",
    "blocking_exceptions",
    "audit_logs",
    "log_processing_state",
    "login_sessions",
}


def test_current_tables():
    assert set(Base.metadata.tables.keys()) == EXPECTED_TABLES


def test_all_foreign_keys_resolve():
    for table in Base.metadata.tables.values():
        for foreign_key in table.foreign_keys:
            assert foreign_key.column is not None


def test_incident_event_composite_primary_key():
    table = Base.metadata.tables["incident_events"]

    primary_keys = {
        column.name
        for column in table.primary_key.columns
    }

    assert primary_keys == {"incident_id", "event_id"}


def test_incident_event_delete_restrictions():
    table = Base.metadata.tables["incident_events"]

    for foreign_key in table.foreign_keys:
        assert foreign_key.ondelete == "RESTRICT"


def test_security_event_fingerprint_unique():
    table = Base.metadata.tables["security_events"]

    assert table.c.event_fingerprint.unique is True


def test_required_unique_constraints():
    expected = {
        "threat_indicators": {
            "indicator_type",
            "indicator_value",
            "source_name",
        },
        "blocking_exceptions": {
            "target_type",
            "target_value",
        },
    }

    for table_name, required_columns in expected.items():
        table = Base.metadata.tables[table_name]

        unique_constraints = [
            {
                column.name
                for column in constraint.columns
            }
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint)
        ]

        assert required_columns in unique_constraints


def test_log_position_is_big_integer():
    table = Base.metadata.tables["log_processing_state"]

    assert table.c.last_position.type.__class__.__name__ == "BigInteger"
    assert table.c.last_position.nullable is False
