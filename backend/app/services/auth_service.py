
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import verify_password
from app.models.administrator import Administrator
from app.models.audit_log import AuditLog


MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


class AccountLockedError(Exception):
    def __init__(self, retry_after: int):
        self.retry_after = max(1, retry_after)
        super().__init__("Account temporarily locked")


def authenticate_admin(
    db: Session,
    username: str,
    password: str,
) -> Administrator | None:

    statement = (
        select(Administrator)
        .where(Administrator.username == username)
        .with_for_update()
    )

    try:
        admin = db.scalar(statement)

        if admin is None or not admin.is_active:
            db.rollback()
            return None

        now = datetime.now(timezone.utc)

        if admin.locked_until is not None:
            locked_until = admin.locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            remaining = (locked_until - now).total_seconds()

            if remaining > 0:
                db.rollback()
                raise AccountLockedError(
                    retry_after=max(1, int(remaining + 0.999999))
                )

            admin.locked_until = None
            admin.failed_login_attempts = 0

        if not verify_password(password, admin.password_hash):
            admin.failed_login_attempts += 1
            db.add(AuditLog(admin_id=admin.admin_id, action_type="LOGIN_FAILURE", target_type="administrator",
                            target_id=str(admin.admin_id), action_result="DENIED"))

            if admin.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                admin.locked_until = (
                    datetime.now(timezone.utc)
                    + timedelta(seconds=LOCKOUT_SECONDS)
                )

                db.commit()
                raise AccountLockedError(
                    retry_after=LOCKOUT_SECONDS
                )

            db.commit()
            return None

        admin.failed_login_attempts = 0
        admin.locked_until = None

        db.commit()
        return admin

    except AccountLockedError:
        raise

    except Exception:
        db.rollback()
        raise
