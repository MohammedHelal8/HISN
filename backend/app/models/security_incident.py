
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Index,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class SecurityIncident(Base):
    __tablename__ = "security_incidents"

    __table_args__ = (
        CheckConstraint(
            "status IN ('NEW', 'UNDER_REVIEW', 'CLOSED')",
            name="ck_security_incident_status",
        ),
        Index(
            "ix_security_incidents_status_created",
            "status",
            "created_at",
        ),
    )

    incident_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    incident_title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    correlation_rule: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default="NEW",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
