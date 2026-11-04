
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    __table_args__ = (
        UniqueConstraint(
            "indicator_type",
            "indicator_value",
            "source_name",
            name="uq_threat_indicator_source",
        ),
        CheckConstraint(
            "indicator_type IN ('DOMAIN', 'IP')",
            name="ck_threat_indicator_type",
        ),
        CheckConstraint(
            "confidence_level IN ('LOW', 'MEDIUM', 'HIGH')",
            name="ck_threat_indicator_confidence",
        ),
        Index(
            "ix_threat_indicator_type_value",
            "indicator_type",
            "indicator_value",
        ),
    )

    indicator_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    indicator_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    indicator_value: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    source_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    confidence_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    last_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Explicit administrator decision; feed sync must never undo it.
    admin_disabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false",
    )

    admin_disabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="true",
    )
