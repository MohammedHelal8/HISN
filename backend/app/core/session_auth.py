"""Opaque database-backed browser sessions. No JWT stored in browser."""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Request
from sqlalchemy.orm import Session
from app.models.login_session import LoginSession
from app.models.audit_log import AuditLog

COOKIE_NAME = "hisn_session"
CSRF_COOKIE = "hisn_csrf"
from app.core.config import settings
SESSION_HOURS = settings.hisn_session_hours  # bounded sessions, not perpetual

def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def create_session(db: Session, user_id: int):
    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    session = LoginSession(user_id=user_id, token_hash=digest(token), csrf_hash=digest(csrf), expires_at=datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS))
    db.add(session)
    db.add(AuditLog(admin_id=user_id, action_type="LOGIN_SUCCESS", target_type="administrator",
                    target_id=str(user_id), action_result="SUCCESS"))
    db.commit()
    return token, csrf

def lookup_session(db: Session, token: str | None):
    if not token:
        return None
    row = db.query(LoginSession).filter(LoginSession.token_hash == digest(token)).first()
    if row is None or row.ended_at is not None or (row.expires_at.replace(tzinfo=timezone.utc) if row.expires_at.tzinfo is None else row.expires_at) <= datetime.now(timezone.utc):
        return None
    return row

def require_csrf(request: Request, row: LoginSession):
    cookie = request.cookies.get(CSRF_COOKIE, "")
    header = request.headers.get("X-CSRF-Token", "")
    if not cookie or not header or not hmac.compare_digest(cookie, header) or not hmac.compare_digest(digest(header), row.csrf_hash):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

def set_session_cookies(response, token: str, csrf: str, secure: bool):
    response.set_cookie(COOKIE_NAME, token, httponly=True, secure=secure, samesite="strict", path="/api", max_age=SESSION_HOURS * 3600)
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=secure, samesite="strict", path="/", max_age=SESSION_HOURS * 3600)

def clear_session_cookies(response):
    response.delete_cookie(COOKIE_NAME, path="/api", samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/", samesite="strict")
