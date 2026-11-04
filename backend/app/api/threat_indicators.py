
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.schemas.common import ConfidenceLevel
from app.models.audit_log import AuditLog

from app.core.auth_dependencies import get_current_admin
from app.core.database import get_db
from app.models.threat_indicator import ThreatIndicator
from app.schemas.threat_indicator import (
    ThreatIndicatorCreate,
    ThreatIndicatorRead,
)
from app.services.threat_indicator_service import (
    DuplicateThreatIndicatorError,
    create_threat_indicator,
)


router = APIRouter(
    prefix="/threat-indicators",
    tags=["Threat Intelligence"],
    dependencies=[Depends(get_current_admin)],
)


@router.get(
    "",
    response_model=list[ThreatIndicatorRead],
)
def list_threat_indicators(
    db: Annotated[Session, Depends(get_db)],
):
    statement = (
        select(ThreatIndicator)
        .order_by(ThreatIndicator.indicator_id)
        .limit(100)
    )

    return db.scalars(statement).all()


@router.post(
    "",
    response_model=ThreatIndicatorRead,
    status_code=status.HTTP_201_CREATED,
)
def add_threat_indicator(
    data: ThreatIndicatorCreate,
    db: Annotated[Session, Depends(get_db)],
    admin=Depends(get_current_admin),
):
    try:
        return create_threat_indicator(db, data, admin_id=admin.admin_id)

    except DuplicateThreatIndicatorError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Threat indicator already exists",
        )



@router.get("/search")
def search_threat_indicators(
    db: Annotated[Session, Depends(get_db)],
    q: str | None = Query(default=None, max_length=255),
    source: str | None = Query(default=None, max_length=100),
    confidence: ConfidenceLevel | None = None,
    active: bool | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    filters = []

    if q and q.strip():
        filters.append(
            ThreatIndicator.indicator_value.ilike(
                "%" + q.strip() + "%"
            )
        )

    if source and source.strip():
        filters.append(
            ThreatIndicator.source_name == source.strip()
        )

    if confidence is not None:
        filters.append(
            ThreatIndicator.confidence_level == confidence.value
        )

    if active is not None:
        filters.append(
            ThreatIndicator.is_active.is_(active)
        )

    total = db.scalar(
        select(func.count(ThreatIndicator.indicator_id))
        .where(*filters)
    ) or 0

    rows = db.scalars(
        select(ThreatIndicator)
        .where(*filters)
        .order_by(ThreatIndicator.indicator_id.desc())
        .limit(limit)
        .offset(offset)
    ).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            ThreatIndicatorRead.model_validate(row).model_dump(mode="json")
            for row in rows
        ],
    }


class IndicatorUpdate(BaseModel):
    is_active: bool
    confidence_level: ConfidenceLevel


@router.patch('/{indicator_id}', response_model=ThreatIndicatorRead)
def update_indicator(indicator_id: int, data: IndicatorUpdate,
                     db: Annotated[Session, Depends(get_db)], admin=Depends(get_current_admin)):
    from datetime import datetime, timezone
    indicator = db.get(ThreatIndicator, indicator_id)
    if indicator is None:
        raise HTTPException(status_code=404, detail='Indicator not found')
    indicator.is_active = data.is_active
    indicator.admin_disabled = not data.is_active
    indicator.admin_disabled_at = datetime.now(timezone.utc) if not data.is_active else None
    indicator.confidence_level = data.confidence_level.value
    indicator.last_updated_at = datetime.now(timezone.utc)
    db.add(AuditLog(admin_id=admin.admin_id, action_type='TI_UPDATE', target_type='threat_indicator',
                    target_id=str(indicator_id), action_result='SUCCESS',
                    details=f'Active: {data.is_active}; confidence: {data.confidence_level.value}'))
    db.commit()
    db.refresh(indicator)
    return indicator
