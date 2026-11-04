"""Transactional processing: event, incident, decision and checkpoint committed together."""
import hashlib
from datetime import datetime, timedelta, timezone
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.threat_indicator import ThreatIndicator
from app.models.blocking_exception import BlockingException
from app.models.security_event import SecurityEvent
from app.models.security_incident import SecurityIncident
from app.models.incident_event import IncidentEvent
from app.models.blocking_action import BlockingAction
from app.models.audit_log import AuditLog
from app.security_engine.log_parser import AccessRecord
from app.security_engine.detection import matches_indicator, indicator_usable, response_decision
from app.integrations.e2guardian import stage_block, PolicyWriteError


def process_record(db: Session, record: AccessRecord, identity: str) -> int:
    """Persist only matched TI events; return count. Caller owns transaction.

    Fingerprint scoped to source and file identity/offset for replay deduplication.
    A repeated access to same destination at a new offset remains a distinct event.
    """
    fingerprint = hashlib.sha256(identity.encode('utf-8')).hexdigest()
    if db.scalar(select(SecurityEvent.event_id).where(SecurityEvent.event_fingerprint == fingerprint)):
        return 0
    now = datetime.now(timezone.utc)
    candidates = db.scalars(select(ThreatIndicator).where(ThreatIndicator.is_active.is_(True))).all()
    matches = [x for x in candidates if indicator_usable(x, now) and matches_indicator(record.destination, x.indicator_type, x.indicator_value)]
    if not matches:
        return 0
    # Store one event per log line. Strongest matching indicator gets precedence.
    confidence_order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    indicator = max(matches, key=lambda x: confidence_order.get(x.confidence_level, 0))
    event = SecurityEvent(event_type='TI_MATCH', activity_at=record.activity_at, client_ip=record.client_ip,
        destination=record.destination, indicator_id=indicator.indicator_id, detection_rule='indicator_match',
        evidence=record.evidence, event_fingerprint=fingerprint)
    db.add(event)
    db.flush()
    since = record.activity_at - timedelta(minutes=settings.hisn_detection_window_minutes)
    # Deterministic window and entity correlation. Unique incident per device+destination
    # within recent window; no artificial severity inferred from confidence.
    existing = db.scalar(select(SecurityIncident).join(IncidentEvent, IncidentEvent.incident_id == SecurityIncident.incident_id)
        .join(SecurityEvent, SecurityEvent.event_id == IncidentEvent.event_id)
        .where(SecurityEvent.client_ip == record.client_ip, SecurityEvent.destination == record.destination,
          SecurityEvent.activity_at >= since, SecurityEvent.event_id != event.event_id,
          SecurityIncident.status != 'CLOSED').order_by(SecurityIncident.incident_id.desc()).limit(1))
    if existing is None:
        existing = SecurityIncident(incident_title=f'Threat indicator match: {record.destination}', correlation_rule='device_destination_window')
        db.add(existing)
        db.flush()
    db.add(IncidentEvent(incident_id=existing.incident_id, event_id=event.event_id))
    recent_count = db.scalar(select(func.count(SecurityEvent.event_id)).where(
        SecurityEvent.client_ip == record.client_ip,
        SecurityEvent.destination == record.destination,
        SecurityEvent.activity_at >= since,
        SecurityEvent.activity_at <= record.activity_at,
    )) or 0
    if recent_count >= settings.hisn_detection_threshold:
        event.event_type = 'REPEATED_MALICIOUS_ACCESS'
        event.detection_rule = 'repeated_ioc_access'
    exceptions = db.scalars(select(BlockingException)).all()
    decision = response_decision(indicator, record.destination, exceptions, allowed=settings.hisn_auto_enforce)
    if decision.action == 'BLOCK_ELIGIBLE':
        # Outbox: never mutate Linux files before DB commits the decision.
        result, error = ('PENDING', None) if settings.hisn_enforcement_enabled else ('DISABLED', 'Policy writer disabled')
    elif decision.action == 'EXCEPTION':
        result, error = 'SKIPPED_EXCEPTION', None
    else:
        result, error = 'ALERT_ONLY', None
    # Record the decision even when it could not be enforced or was alert-only.
    db.add(BlockingAction(indicator_id=indicator.indicator_id, event_id=event.event_id,
        target_value=record.destination, action_source='HISN', decision_reason=decision.reason,
        execution_status=result, error_message=error,
))
    db.add(AuditLog(action_type='TI_DETECTION', target_type='security_event', target_id=str(event.event_id),
        action_result=result, details=f'Indicator source: {indicator.source_name}; {decision.reason}'))
    return 1


def apply_pending_actions(db: Session, batch_size: int = 50) -> int:
    """Process durable pending actions AFTER event/checkpoint commit.

    File appends are idempotent. A crash between file append and DB update leaves
    PENDING, and the next invocation reconciles via ALREADY_STAGED.
    """
    actions = db.scalars(select(BlockingAction).where(BlockingAction.execution_status == 'PENDING')
        .order_by(BlockingAction.action_id).limit(batch_size).with_for_update(skip_locked=True)).all()
    completed = 0
    for action in actions:
        indicator = db.get(ThreatIndicator, action.indicator_id) if action.indicator_id else None
        exceptions = db.scalars(select(BlockingException)).all()
        if indicator is None:
            result, message = 'SKIPPED_INVALID', 'Missing indicator'
        else:
            decision = response_decision(indicator, action.target_value, exceptions, allowed=settings.hisn_auto_enforce)
            if decision.action != 'BLOCK_ELIGIBLE':
                result, message = 'SKIPPED_RECHECK', decision.reason
            elif not settings.hisn_enforcement_enabled:
                result, message = 'DISABLED', 'Policy writer disabled'
            elif indicator.indicator_type != 'DOMAIN':
                result, message = 'UNSUPPORTED_TARGET', 'Destination IP staging is not supported by the domain-list adapter'
            else:
                try:
                    result, message = stage_block(action.target_value, settings.hisn_managed_blocklist), None
                except (PolicyWriteError, OSError) as exc:
                    result, message = 'FAILED', str(exc)[:500]
        action.execution_status = result
        action.error_message = message
        if result in ('STAGED', 'ALREADY_STAGED'):
            action.executed_at = datetime.now(timezone.utc)
        db.add(AuditLog(action_type='POLICY_STAGE', target_type='blocking_action',
            target_id=str(action.action_id), action_result=result, details=message))
        db.commit()
        completed += 1
    return completed
