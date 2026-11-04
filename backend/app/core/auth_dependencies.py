"""Browser authentication: opaque session cookies only (no bearer fallback)."""
from typing import Annotated
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.administrator import Administrator
from app.core.session_auth import COOKIE_NAME, lookup_session, require_csrf


def get_current_user(request: Request, db: Annotated[Session, Depends(get_db)]) -> Administrator:
    row = lookup_session(db, request.cookies.get(COOKIE_NAME))
    if row is None:
        raise HTTPException(status_code=401, detail="Session is missing or expired")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        require_csrf(request, row)
    user = db.get(Administrator, row.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Account is not active")
    if user.role not in ("admin", "viewer"):
        raise HTTPException(status_code=403, detail="Invalid user role")
    return user


def require_admin(user: Annotated[Administrator, Depends(get_current_user)]) -> Administrator:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator privileges required")
    return user


def require_viewer_or_admin(user: Annotated[Administrator, Depends(get_current_user)]) -> Administrator:
    return user

get_current_admin = require_admin
