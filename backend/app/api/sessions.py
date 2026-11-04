"""Administrative view of two-role users and database-backed sessions."""
from datetime import datetime, timezone
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.auth_dependencies import require_admin, get_current_user
from app.core.database import get_db
from app.models.administrator import Administrator
from app.models.login_session import LoginSession
from app.models.audit_log import AuditLog

router = APIRouter(prefix='/administration', tags=['Administration'], dependencies=[Depends(require_admin)])


def as_utc(dt):
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


@router.get('/users')
def users(db: Annotated[Session, Depends(get_db)]):
    return [{'id': x.admin_id, 'username': x.username, 'role': x.role, 'is_active': x.is_active,
             'created_at': x.created_at} for x in db.scalars(select(Administrator).order_by(Administrator.admin_id)).all()]


@router.get('/sessions')
def sessions(db: Annotated[Session, Depends(get_db)], limit: int = Query(50, ge=1, le=100)):
    now = datetime.now(timezone.utc)
    rows = db.scalars(select(LoginSession).order_by(LoginSession.session_id.desc()).limit(limit)).all()
    return [{'session_id': x.session_id, 'user_id': x.user_id, 'created_at': x.created_at,
        'ended_at': x.ended_at, 'expires_at': x.expires_at,
        'active': x.ended_at is None and as_utc(x.expires_at) > now,
        'duration_seconds': max(0, int(((as_utc(x.ended_at) if x.ended_at else min(now, as_utc(x.expires_at))) - as_utc(x.created_at)).total_seconds()))}
        for x in rows]


@router.post('/sessions/{session_id}/revoke')
def revoke(session_id: int, db: Annotated[Session, Depends(get_db)], admin: Annotated[Administrator, Depends(require_admin)]):
    row = db.get(LoginSession, session_id)
    if row is None:
        raise HTTPException(status_code=404, detail='Session not found')
    if row.ended_at is None:
        row.ended_at = datetime.now(timezone.utc)
        db.add(AuditLog(admin_id=admin.admin_id, action_type='SESSION_REVOKE', target_type='login_session',
                        target_id=str(session_id), action_result='SUCCESS'))
        db.commit()
    return {'ok': True}
