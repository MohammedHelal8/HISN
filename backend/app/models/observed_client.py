"""Observed E2Guardian clients, updated transactionally per valid access-log entry."""
from datetime import datetime
from sqlalchemy import BigInteger, DateTime, String, Index, func
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base

class ObservedClient(Base):
    __tablename__ = 'observed_clients'
    __table_args__ = (Index('ix_observed_clients_last_seen', 'last_seen_at'),)
    client_ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    request_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default='0')
    last_destination: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
