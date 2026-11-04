
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


class BlockingAction(Base):
    __tablename__ = "blocking_actions"

    __table_args__ = (
        Index(
            "ix_blocking_actions_execution_status",
            "execution_status",
        ),
        Index(
            "ix_blocking_actions_requested_at",
            "requested_at",
        ),
    )

    action_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    indicator_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("threat_indicators.indicator_id"),
        nullable=True,
    )

    event_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("security_events.event_id"),
        nullable=True,
    )

    target_value: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    action_source: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    decision_reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    execution_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        server_default="PENDING",
    )

    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    executed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    admin_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("administrators.admin_id"),
        nullable=True,
    )
