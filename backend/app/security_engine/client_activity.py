"""Track observed clients; not network discovery, not immutable device identity."""
import ipaddress
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.observed_client import ObservedClient
from app.security_engine.log_parser import AccessRecord


def is_observed_endpoint(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)
    except ValueError:
        return False


def record_client_activity(db: Session, record: AccessRecord) -> None:
    """Called once per new parsed line in the log worker transaction.

    Older/later log lines must not move last_seen backwards. Worker checkpoint
    and observation are committed atomically; retries after commit skip the line.
    """
    if record.source != 'e2guardian' or not is_observed_endpoint(record.client_ip):
        return
    client = db.scalar(select(ObservedClient).where(ObservedClient.client_ip == record.client_ip).with_for_update())
    moment = record.activity_at
    if client is None:
        db.add(ObservedClient(client_ip=record.client_ip, first_seen_at=moment,
                              last_seen_at=moment, request_count=1,
                              last_destination=record.destination))
    else:
        if moment < client.first_seen_at:
            client.first_seen_at = moment
        if moment >= client.last_seen_at:
            client.last_seen_at = moment
            client.last_destination = record.destination
        client.request_count += 1
        client.updated_at = datetime.now(timezone.utc)
