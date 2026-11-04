"""Read-only security activity grouped by observed client IP."""

import ipaddress
from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.core.auth_dependencies import require_viewer_or_admin
from app.core.database import get_db
from app.models.security_event import SecurityEvent
from app.models.incident_event import IncidentEvent


router = APIRouter(
    prefix="/clients",
    tags=["Client Security"],
    dependencies=[Depends(require_viewer_or_admin)],
)


def is_endpoint_candidate(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return not (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
        )
    except ValueError:
        return False


@router.get("")
def list_clients(db: Session = Depends(get_db)):
    event_rows = db.execute(
        select(
            SecurityEvent.client_ip,
            func.count(SecurityEvent.event_id),
            func.max(SecurityEvent.activity_at),
        )
        .group_by(SecurityEvent.client_ip)
    ).all()

    incident_rows = db.execute(
        select(
            SecurityEvent.client_ip,
            func.count(
                func.distinct(IncidentEvent.incident_id)
            ),
        )
        .join(
            IncidentEvent,
            IncidentEvent.event_id == SecurityEvent.event_id,
        )
        .group_by(SecurityEvent.client_ip)
    ).all()

    incident_counts = {
        ip: count for ip, count in incident_rows
    }

    clients = []

    for ip, count, last_activity in event_rows:
        if not is_endpoint_candidate(ip):
            continue

        clients.append({
            "client_ip": ip,
            "events": count,
            "incidents": incident_counts.get(ip, 0),
            "last_activity": last_activity,
        })

    clients.sort(
        key=lambda item: item["last_activity"],
        reverse=True,
    )

    return {
        "total": len(clients),
        "clients": clients,
        "note": (
            "Observed security activity only. "
            "An IP address is not a guaranteed unique device identity."
        ),
    }
