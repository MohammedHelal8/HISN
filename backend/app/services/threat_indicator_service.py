
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
try:
    from psycopg.errors import UniqueViolation
except ImportError:  # SQLite unit tests; PostgreSQL deployments install psycopg
    UniqueViolation = ()
from app.models.threat_indicator import ThreatIndicator
from app.models.audit_log import AuditLog
from app.schemas.threat_indicator import ThreatIndicatorCreate


class DuplicateThreatIndicatorError(Exception):
    pass


def get_threat_indicator(
    db: Session,
    indicator_type: str,
    indicator_value: str,
    source_name: str,
) -> ThreatIndicator | None:
    statement = select(ThreatIndicator).where(
        ThreatIndicator.indicator_type == indicator_type,
        ThreatIndicator.indicator_value == indicator_value,
        ThreatIndicator.source_name == source_name,
    )

    return db.scalar(statement)


def create_threat_indicator(
    db: Session,
    data: ThreatIndicatorCreate,
    admin_id: int | None = None,
) -> ThreatIndicator:
    existing = get_threat_indicator(
        db=db,
        indicator_type=data.indicator_type.value,
        indicator_value=data.indicator_value,
        source_name=data.source_name,
    )

    if existing is not None:
        raise DuplicateThreatIndicatorError(
            "Threat indicator already exists for this source"
        )

    indicator = ThreatIndicator(
        indicator_type=data.indicator_type.value,
        indicator_value=data.indicator_value,
        source_name=data.source_name,
        confidence_level=data.confidence_level.value,
        expires_at=data.expires_at,
        is_active=True,
    )

    db.add(indicator)
    if admin_id is not None:
        db.add(AuditLog(admin_id=admin_id, action_type="TI_CREATE", target_type="threat_indicator",
                        target_id=data.indicator_value, action_result="SUCCESS",
                        details=f"Source: {data.source_name}; confidence: {data.confidence_level.value}"))

   

    try:
        db.commit()

    except IntegrityError as exc:
        db.rollback()

        original_error = exc.orig

        if isinstance(original_error, UniqueViolation):
            constraint_name = getattr(
                getattr(original_error, "diag", None),
                "constraint_name",
                None,
            )

            if constraint_name == "uq_threat_indicator_source":
                raise DuplicateThreatIndicatorError(
                    "Threat indicator already exists for this source"
                ) from exc

        raise



    db.refresh(indicator)

    return indicator
