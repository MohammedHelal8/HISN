
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class LogProcessingState(Base):
    __tablename__ = "log_processing_state"

    state_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    log_source: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )

    file_identity: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    last_position: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        server_default="0",
    )

    last_processed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
