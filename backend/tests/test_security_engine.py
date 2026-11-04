"""Offline rules and SQLite simulation; does not claim PostgreSQL/systemd integration."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from pathlib import Path
from sqlalchemy import BigInteger, create_engine, select, func
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import pytest
import app.models
from app.core.database import Base
from app.core.config import settings
from app.models.threat_indicator import ThreatIndicator
from app.models.blocking_exception import BlockingException
from app.models.administrator import Administrator
from app.models.blocking_action import BlockingAction
from app.models.security_event import SecurityEvent
from app.models.security_incident import SecurityIncident
from app.models.log_processing_state import LogProcessingState
from app.security_engine.log_parser import parse_access_log, normalize_destination
from app.security_engine.detection import matches_indicator, response_decision
from app.jobs.worker import ingest_once
from app.integrations.e2guardian import stage_block, PolicyWriteError


@compiles(BigInteger, 'sqlite')
def sqlite_bigint(_type, _compiler, **kw):
    return 'INTEGER'


@pytest.fixture
def session_factory():
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    yield factory
    Base.metadata.drop_all(engine)
    engine.dispose()


def test_parser_supported_layouts_redacts_urls():
    parsed = parse_access_log('2026.10.30 10:00:00 alice 10.2.3.4 https://danger.example/path?token=SECRET DENIED 403\n')
    assert parsed.client_ip == '10.2.3.4'
    assert parsed.destination == 'danger.example'
    assert 'SECRET' not in parsed.evidence
    squid = parse_access_log('1793354400.000 15 10.2.3.4 TCP_MISS/200 600 GET http://danger.example/a?key=SECRET - DIRECT/1.2.3.4 text/html')
    assert squid and squid.destination == 'danger.example' and 'SECRET' not in squid.evidence
    assert parse_access_log('missing all relevant fields') is None
    assert parse_access_log('2026.10.30 10:00:00 alice INVALID http://danger.example DENIED 403') is None


@pytest.mark.parametrize('url,expected', [
    ('https://sub.evil.example/path', 'sub.evil.example'),
    ('EVIL.EXAMPLE.', 'evil.example'),
    ('https://[2001:db8::1]/', '2001:db8::1'),
])
def test_destination_normalization(url, expected):
    assert normalize_destination(url) == expected


@pytest.mark.parametrize('url', ['javascript:alert(1)', 'http://user:pass@evil.example', 'evil.example/private', 'localdomain', 'https://bad example.com'])
def test_bad_destinations_rejected(url):
    with pytest.raises(ValueError):
        normalize_destination(url)


def test_domain_boundary_prevents_overblocking():
    assert matches_indicator('sub.bad.example', 'DOMAIN', 'bad.example')
    assert not matches_indicator('notbad.example', 'DOMAIN', 'bad.example')
    assert not matches_indicator('bad.example.attacker.com', 'DOMAIN', 'bad.example')
    assert matches_indicator('198.51.100.2', 'IP', '198.51.100.2')
    assert not matches_indicator('198.51.100.21', 'IP', '198.51.100.2')


def test_decisions_expiry_confidence_exception():
    now = datetime.now(timezone.utc)
    indicator = SimpleNamespace(is_active=True, expires_at=now + timedelta(days=1), indicator_type='DOMAIN',
                                indicator_value='bad.example', confidence_level='HIGH', source_name='sample')
    assert response_decision(indicator, 'sub.bad.example', [], allowed=True).action == 'BLOCK_ELIGIBLE'
    assert response_decision(indicator, 'bad.example', [SimpleNamespace(target_type='DOMAIN', target_value='bad.example')], allowed=True).action == 'EXCEPTION'
    indicator.confidence_level = 'LOW'
    assert response_decision(indicator, 'bad.example', [], allowed=True).action == 'ALERT_ONLY'
    indicator.expires_at = now - timedelta(seconds=1)
    indicator.confidence_level = 'HIGH'
    assert response_decision(indicator, 'bad.example', [], allowed=True).action == 'ALERT_ONLY'


def test_ingestion_checkpoint_dedup_correlation_and_rotation(session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'hisn_auto_enforce', False)
    log = tmp_path / 'access.log'
    log.write_text('2026.10.30 10:00:00 alice 10.2.3.4 http://bad.example/1 DENIED 403\n'
                   '2026.10.30 10:01:00 alice 10.2.3.4 http://bad.example/2 DENIED 403\n'
                   'not a supported log layout\n', encoding='utf8')
    with session_factory() as db:
        db.add(ThreatIndicator(indicator_type='DOMAIN', indicator_value='bad.example', source_name='test', confidence_level='HIGH', is_active=True))
        db.commit()
    result = ingest_once(str(log), session_factory)
    assert result == {'read': 3, 'matched': 2, 'invalid': 1}
    assert ingest_once(str(log), session_factory) == {'read': 0, 'matched': 0, 'invalid': 0}
    with session_factory() as db:
        assert db.scalar(select(func.count()).select_from(SecurityEvent)) == 2
        assert db.scalar(select(func.count()).select_from(SecurityIncident)) == 1
        assert db.scalars(select(BlockingAction.execution_status)).all() == ['ALERT_ONLY', 'ALERT_ONLY']
        state = db.scalar(select(LogProcessingState))
        assert state.last_position == log.stat().st_size
    rotated = tmp_path / 'access.log.1'
    log.rename(rotated)
    log.write_text('2026.10.30 10:02:00 alice 10.2.3.4 http://bad.example/3 DENIED 403\n', encoding='utf8')
    assert ingest_once(str(log), session_factory)['matched'] == 1
    with session_factory() as db:
        assert db.scalar(select(func.count()).select_from(SecurityEvent)) == 3
        assert db.scalar(select(func.count()).select_from(SecurityIncident)) == 1


def test_partial_line_not_advanced(session_factory, tmp_path):
    log = tmp_path / 'incomplete.log'
    log.write_text('2026.10.30 10:00:00 alice 10.2.3.4 http://bad.example DENIED 403', encoding='utf8')
    assert ingest_once(str(log), session_factory)['read'] == 0
    with log.open('a') as f:
        f.write('\n')
    assert ingest_once(str(log), session_factory)['read'] == 1


def test_mocked_staging_does_not_claim_enforced(tmp_path):
    path = tmp_path / 'hisn-managed.list'
    path.write_text('# HISN-owned test list\n')
    path.chmod(0o600)
    assert stage_block('bad.example', str(path)) == 'STAGED'
    assert stage_block('bad.example', str(path)) == 'ALREADY_STAGED'
    assert path.read_text().count('bad.example') == 1
    with pytest.raises(PolicyWriteError):
        stage_block('bad.example', '/no/such/blocklist')
    path.chmod(0o666)
    with pytest.raises(PolicyWriteError):
        stage_block('bad.example', str(path))


def test_repeated_access_rule_threshold(session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'hisn_detection_threshold', 2)
    monkeypatch.setattr(settings, 'hisn_auto_enforce', False)
    log = tmp_path / 'rule.log'
    log.write_text('2026.10.30 10:00:00 a 10.2.3.4 http://bad.example/a DENIED 403\n'
                   '2026.10.30 10:02:00 a 10.2.3.4 http://bad.example/b DENIED 403\n')
    with session_factory() as db:
        db.add(ThreatIndicator(indicator_type='DOMAIN', indicator_value='bad.example', source_name='test', confidence_level='LOW', is_active=True))
        db.commit()
    assert ingest_once(str(log), session_factory)['matched'] == 2
    with session_factory() as db:
        assert [x.event_type for x in db.scalars(select(SecurityEvent).order_by(SecurityEvent.event_id))] == ['TI_MATCH', 'REPEATED_MALICIOUS_ACCESS']


def test_enforcement_outbox_recovery(session_factory, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'hisn_auto_enforce', True)
    monkeypatch.setattr(settings, 'hisn_enforcement_enabled', True)
    blockfile = tmp_path / 'managed.list'
    blockfile.write_text('')
    blockfile.chmod(0o600)
    monkeypatch.setattr(settings, 'hisn_managed_blocklist', str(blockfile))
    log = tmp_path / 'access.log'
    log.write_text('2026.10.30 10:00:00 alice 10.2.3.4 https://bad.example/b DENIED 403\n')
    with session_factory() as db:
        db.add(ThreatIndicator(indicator_type='DOMAIN', indicator_value='bad.example', source_name='test', confidence_level='HIGH', is_active=True))
        db.commit()
    assert ingest_once(str(log), session_factory)['matched'] == 1
    with session_factory() as db:
        action = db.scalar(select(BlockingAction))
        assert action.execution_status == 'STAGED'
        # Simulate a crash after the file append but before status commit.
        action.execution_status = 'PENDING'
        db.commit()
    assert ingest_once(str(log), session_factory)['read'] == 0
    with session_factory() as db:
        assert db.scalar(select(BlockingAction)).execution_status == 'ALREADY_STAGED'
    assert blockfile.read_text().splitlines() == ['bad.example']


def test_oversized_complete_line_skipped_without_stalling(session_factory, tmp_path):
    log = tmp_path / 'oversized.log'
    log.write_text('x' * 20000 + '\n' + '2026.10.30 10:00:00 a 10.2.3.4 http://safe.example ALLOWED 200\n')
    assert ingest_once(str(log), session_factory) == {'read': 2, 'matched': 0, 'invalid': 1}
    assert ingest_once(str(log), session_factory)['read'] == 0


def test_e2guardian_timezone_is_configurable(monkeypatch):
    monkeypatch.setattr(settings, 'hisn_log_timezone', 'Asia/Aden')
    parsed = parse_access_log('2026.10.30 13:00:00 a 10.2.3.4 http://bad.example DENIED 403')
    assert parsed.activity_at.hour == 10
