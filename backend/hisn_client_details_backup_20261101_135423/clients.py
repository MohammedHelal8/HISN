"""Read-only, auto-discovered E2Guardian activity for authenticated users."""
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from app.core.auth_dependencies import require_viewer_or_admin
from app.core.database import get_db
from app.models.observed_client import ObservedClient
from app.models.security_event import SecurityEvent
from app.models.incident_event import IncidentEvent

router = APIRouter(prefix='/clients', tags=['Client Security'], dependencies=[Depends(require_viewer_or_admin)])

@router.get('')
def list_clients(db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    """Observed requests, NOT number of currently connected network devices."""
    total = db.scalar(select(func.count()).select_from(ObservedClient)) or 0
    clients = db.scalars(select(ObservedClient).order_by(ObservedClient.last_seen_at.desc(), ObservedClient.client_ip)
                        .offset(offset).limit(limit)).all()
    ips = [c.client_ip for c in clients]
    events = {}
    incidents = {}
    if ips:
        events = dict(db.execute(select(SecurityEvent.client_ip, func.count(SecurityEvent.event_id))
                                 .where(SecurityEvent.client_ip.in_(ips)).group_by(SecurityEvent.client_ip)).all())
        incidents = dict(db.execute(select(SecurityEvent.client_ip, func.count(func.distinct(IncidentEvent.incident_id)))
                                    .join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.event_id)
                                    .where(SecurityEvent.client_ip.in_(ips)).group_by(SecurityEvent.client_ip)).all())
    now = datetime.now(timezone.utc)
    return {'total': total, 'limit': limit, 'offset': offset,
            'clients': [{'client_ip': c.client_ip, 'first_seen_at': c.first_seen_at,
                         'last_activity': c.last_seen_at, 'requests': c.request_count,
                         'last_destination': c.last_destination,
                         'active_recently': c.last_seen_at >= now - timedelta(minutes=5),
                         'events': events.get(c.client_ip, 0), 'incidents': incidents.get(c.client_ip, 0)}
                        for c in clients],
            'note': 'Observed through E2Guardian. Recent activity is not an online connectivity check; IP is not a persistent device identity.'}
