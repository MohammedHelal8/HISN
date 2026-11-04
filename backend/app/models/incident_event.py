
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    incident_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey(
            "security_incidents.incident_id",
            ondelete="RESTRICT",
        ),
        primary_key=True,
    )

    event_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey(
            "security_events.event_id",
            ondelete="RESTRICT",
        ),
        primary_key=True,
    )

    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
