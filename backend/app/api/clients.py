"""Observed E2Guardian client list, filters, and security-event timeline.

Request history is not fabricated: observed_clients holds aggregate request stats,
not individual request lines. Times represent observed activity, not online presence.
"""
import ipaddress
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, exists, and_
from sqlalchemy.orm import Session
from app.core.auth_dependencies import require_viewer_or_admin, require_admin
from app.core.database import get_db
from app.models.observed_client import ObservedClient
from app.models.security_event import SecurityEvent
from app.models.incident_event import IncidentEvent

router = APIRouter(prefix='/clients', tags=['Client Security'], dependencies=[Depends(require_viewer_or_admin)])

def _statistics(db, ips):
    if not ips:
        return {}, {}
    events = dict(db.execute(
        select(SecurityEvent.client_ip, func.count(SecurityEvent.event_id))
        .where(SecurityEvent.client_ip.in_(ips))
        .group_by(SecurityEvent.client_ip)
    ).all())
    incidents = dict(db.execute(
        select(SecurityEvent.client_ip, func.count(func.distinct(IncidentEvent.incident_id)))
        .join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.event_id)
        .where(SecurityEvent.client_ip.in_(ips))
        .group_by(SecurityEvent.client_ip)
    ).all())
    return events, incidents

def _client_payload(c, now, events, incidents):
    return {'client_ip': c.client_ip,
            'first_seen_at': c.first_seen_at,
            'last_activity': c.last_seen_at,
            'requests': c.request_count,
            'last_destination': c.last_destination,
            'active_recently': c.last_seen_at >= now - timedelta(minutes=5),
            'events': events.get(c.client_ip, 0),
            'incidents': incidents.get(c.client_ip, 0)}

@router.get('')
def list_clients(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    view: str = Query('recent', pattern='^(recent|all|threats)$'),
    q: str = Query('', max_length=45),
):
    now = datetime.now(timezone.utc)
    query = select(ObservedClient)
    if q.strip():
        # Literal substring match; escape LIKE metacharacters supplied by users.
        term = q.strip().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        query = query.where(ObservedClient.client_ip.ilike(f'%{term}%', escape='\\'))
    if view == 'recent':
        query = query.where(ObservedClient.last_seen_at >= now - timedelta(minutes=5))
    elif view == 'threats':
        query = query.where(exists(select(SecurityEvent.event_id).where(
            SecurityEvent.client_ip == ObservedClient.client_ip)))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    clients = db.scalars(query.order_by(ObservedClient.last_seen_at.desc(), ObservedClient.client_ip)
                         .offset(offset).limit(limit)).all()
    events, incidents = _statistics(db, [c.client_ip for c in clients])
    return {'total': total, 'limit': limit, 'offset': offset, 'view': view,
            'clients': [_client_payload(c, now, events, incidents) for c in clients],
            'note': 'Recent activity is not proof of network connectivity; IP addresses may be shared or reassigned.'}

@router.get('/{client_ip}')
def client_details(client_ip: str, db: Session = Depends(get_db), _admin=Depends(require_admin),
                   limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
    try:
        ipaddress.ip_address(client_ip)
    except ValueError:
        raise HTTPException(status_code=422, detail='Invalid client IP')
    client = db.get(ObservedClient, client_ip)
    if client is None:
        raise HTTPException(status_code=404, detail='Client not observed')
    now = datetime.now(timezone.utc)
    events_counts, incidents_counts = _statistics(db, [client_ip])
    base = select(SecurityEvent).where(SecurityEvent.client_ip == client_ip)
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    events = db.scalars(base.order_by(SecurityEvent.activity_at.desc(), SecurityEvent.event_id.desc())
                        .offset(offset).limit(limit)).all()
    event_ids = [e.event_id for e in events]
    incident_map = {}
    if event_ids:
        for event_id, incident_id in db.execute(
            select(IncidentEvent.event_id, IncidentEvent.incident_id)
            .where(IncidentEvent.event_id.in_(event_ids))
        ).all():
            incident_map.setdefault(event_id, []).append(incident_id)
    return {
        'client': _client_payload(client, now, events_counts, incidents_counts),
        'security_events_total': total, 'limit': limit, 'offset': offset,
        'security_events': [
            {'event_id': e.event_id, 'event_type': e.event_type,
             'activity_at': e.activity_at, 'detected_at': e.detected_at,
             'destination': e.destination, 'detection_rule': e.detection_rule,
             'indicator_id': e.indicator_id, 'evidence': e.evidence,
             'incident_ids': incident_map.get(e.event_id, [])}
            for e in events
        ],
        'request_history_available': False,
        'request_history_note': ('The observed_clients table stores totals, first/last times, and last destination. '
                                 'It does not store individual normal web requests. Security events below are recorded history.'),
    }
