
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class BlockingException(Base):
    __tablename__ = "blocking_exceptions"

    __table_args__ = (
        UniqueConstraint(
            "target_type",
            "target_value",
            name="uq_blocking_exception_target",
        ),
        CheckConstraint(
            "target_type IN ('DOMAIN', 'IP')",
            name="ck_blocking_exception_type",
        ),
        Index(
            "ix_blocking_exception_target",
            "target_type",
            "target_value",
        ),
    )

    exception_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    target_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    target_value: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    created_by: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("administrators.admin_id"),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
