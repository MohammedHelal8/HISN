from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.session_auth import (COOKIE_NAME, clear_session_cookies, create_session, lookup_session, require_csrf, set_session_cookies)
from app.services.auth_service import AccountLockedError, authenticate_admin
from app.models.audit_log import AuditLog

router = APIRouter(prefix="/auth", tags=["Authentication"])
class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)

@router.post("/login")
def login(credentials: LoginRequest, response: Response, request: Request, db: Annotated[Session, Depends(get_db)]):
    try:
        user = authenticate_admin(db, credentials.username, credentials.password)
    except AccountLockedError as exc:
        raise HTTPException(status_code=429, detail="Too many failed login attempts", headers={"Retry-After": str(exc.retry_after)}) from exc
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    # For production HTTPS set HISN_COOKIE_SECURE=true (default); for local HTTP development set false.
    from app.core.config import settings
    token, csrf = create_session(db, user.admin_id)
    set_session_cookies(response, token, csrf, settings.hisn_cookie_secure)
    response.headers["Cache-Control"] = "no-store"
    return {"ok": True}

@router.post("/logout")
def logout(response: Response, request: Request, db: Annotated[Session, Depends(get_db)]):
    token = request.cookies.get(COOKIE_NAME)
    row = lookup_session(db, token)
    if row:
        require_csrf(request, row)
        from datetime import datetime, timezone
        row.ended_at = datetime.now(timezone.utc)
        db.add(AuditLog(admin_id=row.user_id, action_type="LOGOUT", target_type="login_session",
                        target_id=str(row.session_id), action_result="SUCCESS"))
        db.commit()
    clear_session_cookies(response)
    response.headers["Cache-Control"] = "no-store"
    return {"ok": True}
