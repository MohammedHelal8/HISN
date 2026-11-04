"""Strict allowlisted service management, no arbitrary shell expansion or root escalation."""
import platform
import subprocess
from typing import Annotated, Literal
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.core.auth_dependencies import require_admin
from app.core.database import get_db
from app.core.config import settings
from app.models.administrator import Administrator
from app.models.audit_log import AuditLog

router = APIRouter(prefix='/services', tags=['Service Administration'], dependencies=[Depends(require_admin)])
SERVICE_UNITS = {'squid': 'squid.service', 'e2guardian': 'e2guardian.service'}
ACTIONS = {'start', 'stop', 'restart', 'reload'}


@router.post('/{service}/{action}')
def control_service(service: Literal['squid', 'e2guardian'], action: Literal['start', 'stop', 'restart', 'reload'],
                    db: Annotated[Session, Depends(get_db)], admin: Annotated[Administrator, Depends(require_admin)]):
    # Additional deploy-time guard beyond RBAC. Grant narrow polkit permission if desired.
    if not getattr(settings, 'hisn_service_control_enabled', False):
        raise HTTPException(status_code=403, detail='Service control is disabled')
    if platform.system() != 'Linux':
        raise HTTPException(status_code=503, detail='Service control requires Linux')
    try:
        result = subprocess.run(['/usr/bin/systemctl', action, SERVICE_UNITS[service]],
                                capture_output=True, text=True, timeout=12, check=False)
        success = result.returncode == 0
        error = '' if success else 'Service action was rejected or failed; inspect system journal'
    except (OSError, subprocess.TimeoutExpired):
        success, error = False, 'Service action failed or timed out'
    db.add(AuditLog(admin_id=admin.admin_id, action_type=f'SERVICE_{action.upper()}', target_type='systemd_unit',
                    target_id=SERVICE_UNITS[service], action_result='SUCCESS' if success else 'FAILED', details=error))
    db.commit()
    if not success:
        raise HTTPException(status_code=503, detail=error)
    return {'ok': True, 'unit': SERVICE_UNITS[service], 'operation': action,
        'note': 'Command completed; verify service health separately'}


@router.get('/{service}/logs')
def service_logs(service: Literal['squid', 'e2guardian'], limit: int = Query(50, ge=1, le=100)):
    """Read bounded, sanitized parsed lines; do not disclose raw URL query tokens."""
    from pathlib import Path
    from app.security_engine.log_parser import parse_access_log
    path = Path(settings.hisn_squid_log if service == 'squid' else settings.hisn_e2guardian_log)
    try:
        if not path.is_file() or path.is_symlink():
            raise OSError('Log is unavailable or not a regular file')
        with path.open('rb') as handle:
            size = path.stat().st_size
            handle.seek(max(0, size - 512 * 1024))
            if size > 512 * 1024:
                handle.readline()  # drop truncated first line
            lines = handle.readlines()
    except OSError as exc:
        raise HTTPException(status_code=503, detail='The service log is not available to HISN') from exc
    results = []
    for line in lines[-max(limit * 8, limit):]:
        entry = parse_access_log(line[:16384].decode('utf-8', 'replace'))
        if entry is None or entry.source != service:
            continue
        results.append({'time': entry.activity_at, 'client_ip': entry.client_ip,
                        'destination': entry.destination, 'action': entry.action})
    return results[-limit:]
