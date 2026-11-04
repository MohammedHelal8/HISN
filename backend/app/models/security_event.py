
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


class SecurityEvent(Base):
    __tablename__ = "security_events"

    __table_args__ = (
        Index(
            "ix_security_events_detected_at",
            "detected_at",
        ),
        Index(
            "ix_security_events_client_ip",
            "client_ip",
        ),
        Index(
            "ix_security_events_destination",
            "destination",
        ),
    )

    event_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    client_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
    )

    destination: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    indicator_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("threat_indicators.indicator_id"),
        nullable=True,
    )

    detection_rule: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    evidence: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    event_fingerprint: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
    )
