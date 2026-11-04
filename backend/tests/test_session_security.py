"""Actual FastAPI endpoints exercising HttpOnly cookies, CSRF, logout and RBAC."""
from sqlalchemy import BigInteger, create_engine, select
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
import pytest
import app.models
from app.main import app
from app.core.config import settings
from app.core.database import Base, get_db
from app.core.security import hash_password
from app.models.administrator import Administrator

@compiles(BigInteger, 'sqlite')
def sqlite_bigint(_type, _compiler, **kw):
    return 'INTEGER'

@pytest.fixture
def web_client(monkeypatch):
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as db:
        db.add(Administrator(username='admin', password_hash=hash_password('TestPass2026!secure'), role='admin', is_active=True))
        db.add(Administrator(username='viewer', password_hash=hash_password('ViewerPass2026!secure'), role='viewer', is_active=True))
        db.commit()
    monkeypatch.setattr(settings, 'hisn_cookie_secure', False)
    def override():
        with factory() as db:
            yield db
    app.dependency_overrides[get_db] = override
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_login_restore_csrf_logout(web_client):
    client = web_client
    response = client.post('/api/auth/login', json={'username':'admin','password':'TestPass2026!secure'})
    assert response.status_code == 200
    assert 'httponly' in response.headers['set-cookie'].lower()
    assert client.get('/api/users/me').json()['role'] == 'admin'
    assert client.get('/api/security/summary').status_code == 200
    # Cookie-authenticated mutations are never authorized without CSRF header.
    assert client.post('/api/security/preview', json={'destination':'example.org'}).status_code == 403
    csrf = client.cookies.get('hisn_csrf')
    assert client.post('/api/security/preview', json={'destination':'example.org'}, headers={'X-CSRF-Token':csrf}).status_code == 200
    assert client.post('/api/auth/logout').status_code == 403
    assert client.post('/api/auth/logout', headers={'X-CSRF-Token':csrf}).status_code == 200
    assert client.get('/api/users/me').status_code == 401


def test_viewer_forbidden_admin_apis(web_client):
    client = web_client
    assert client.post('/api/auth/login', json={'username':'viewer','password':'ViewerPass2026!secure'}).status_code == 200
    assert client.get('/api/users/me').json()['role'] == 'viewer'
    assert client.get('/api/security/events').status_code == 403
    assert client.get('/api/administration/users').status_code == 403


def test_lockout_after_five_wrong_passwords(web_client):
    client = web_client
    for i in range(4):
        assert client.post('/api/auth/login', json={'username':'admin','password':'bad'}).status_code == 401
    assert client.post('/api/auth/login', json={'username':'admin','password':'bad'}).status_code == 429
    assert client.post('/api/auth/login', json={'username':'admin','password':'TestPass2026!secure'}).status_code == 429


def test_admin_ti_exception_and_preview_api(web_client):
    client = web_client
    assert client.post('/api/auth/login', json={'username':'admin','password':'TestPass2026!secure'}).status_code == 200
    csrf = client.cookies.get('hisn_csrf')
    headers = {'X-CSRF-Token': csrf}
    create = client.post('/api/threat-indicators', headers=headers,
        json={'indicator_type':'DOMAIN', 'indicator_value':'bad.example', 'source_name':'test-verified', 'confidence_level':'HIGH'})
    assert create.status_code == 201, create.text
    indicator_id = create.json()['indicator_id']
    preview = client.post('/api/security/preview', headers=headers, json={'destination':'sub.bad.example'})
    assert preview.status_code == 200
    assert len(preview.json()['matches']) == 1
    exc = client.post('/api/security/exceptions', headers=headers, json={'target_type':'DOMAIN', 'target_value':'bad.example'})
    assert exc.status_code == 201
    changed = client.patch(f'/api/threat-indicators/{indicator_id}', headers=headers,
        json={'is_active': False, 'confidence_level':'LOW'})
    assert changed.status_code == 200 and changed.json()['is_active'] is False
    # Cross-origin writes are blocked before reaching authenticated routes.
    forged = client.post('/api/security/preview', headers={**headers, 'Origin':'https://evil.example'},
                         json={'destination':'bad.example'})
    assert forged.status_code == 403
    assert client.get('/api/security/audit').status_code == 200


def test_service_actions_disabled_and_logs_sanitized(web_client, monkeypatch, tmp_path):
    client = web_client
    assert client.post('/api/auth/login', json={'username':'admin','password':'TestPass2026!secure'}).status_code == 200
    csrf = client.cookies.get('hisn_csrf')
    assert client.post('/api/services/squid/restart', headers={'X-CSRF-Token': csrf}).status_code == 403
    assert client.post('/api/services/squid/evil;rm', headers={'X-CSRF-Token': csrf}).status_code == 422
    logfile = tmp_path / 'squid.log'
    logfile.write_text('1793354400.000 15 10.2.3.4 TCP_MISS/200 600 GET http://bad.example/private?key=SECRET - DIRECT/1.2.3.4 text/html\n')
    monkeypatch.setattr(settings, 'hisn_squid_log', str(logfile))
    response = client.get('/api/services/squid/logs')
    assert response.status_code == 200
    assert response.json()[0]['destination'] == 'bad.example'
    assert 'SECRET' not in response.text
