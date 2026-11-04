
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    __table_args__ = (
        Index(
            "ix_audit_logs_created_at",
            "created_at",
        ),
    )

    audit_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    admin_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("administrators.admin_id"),
        nullable=True,
    )

    action_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    target_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    target_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    action_result: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    details: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
