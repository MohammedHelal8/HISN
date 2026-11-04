"""Read-only HISN enforcement preflight. Never applies blocks."""

import ipaddress
import re
import stat
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.blocking_action import BlockingAction
from app.models.blocking_exception import BlockingException
from app.models.threat_indicator import ThreatIndicator
from app.security_engine.detection import (
    indicator_usable,
    response_decision,
)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def valid_domain(value):
    if not isinstance(value, str):
        return False
    if value != value.strip().lower():
        return False
    if not DOMAIN_RE.fullmatch(value):
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        return True


def inspect_file():
    value = settings.hisn_managed_blocklist
    if not value:
        raise RuntimeError("Managed blocklist not configured")

    path = Path(value)

    if not path.is_absolute() or path.is_symlink():
        raise RuntimeError("Unsafe managed path")

    info = path.stat()

    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError("Managed path is not a regular file")

    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError("Managed file has unsafe permissions")

    if path.parent.is_symlink():
        raise RuntimeError("Managed directory is a symlink")

    if path.parent.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError("Managed directory is writable by group/others")

    domains = set()
    invalid = []

    for number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        entry = line.strip()

        if not entry or entry.startswith("#"):
            continue

        if valid_domain(entry):
            domains.add(entry)
        else:
            invalid.append(number)

    return path, domains, invalid


def main():
    print("=== HISN ENFORCEMENT DRY RUN ===")
    print("Automatic enforcement:", settings.hisn_auto_enforce)
    print("Policy writer enabled:", settings.hisn_enforcement_enabled)

    path, staged_domains, invalid_lines = inspect_file()

    print("Managed file:", path)
    print("Staged domains:", len(staged_domains))
    print("Invalid file lines:", invalid_lines)

    statuses = Counter()

    with SessionLocal() as db:
        actions = db.scalars(
            select(BlockingAction)
            .where(
                BlockingAction.execution_status.in_(
                    ["PENDING", "STAGED", "ALREADY_STAGED"]
                )
            )
            .order_by(BlockingAction.action_id)
            .limit(100)
        ).all()

        exceptions = db.scalars(
            select(BlockingException)
        ).all()

        now = datetime.now(timezone.utc)

        for action in actions:
            indicator = (
                db.get(ThreatIndicator, action.indicator_id)
                if action.indicator_id is not None
                else None
            )

            reason = None

            if indicator is None:
                reason = "MISSING_INDICATOR"

            elif not indicator.is_active:
                reason = "INACTIVE_INDICATOR"

            elif getattr(indicator, "admin_disabled", False):
                reason = "ADMIN_DISABLED"

            elif indicator.confidence_level != "HIGH":
                reason = "NOT_HIGH_CONFIDENCE"

            elif indicator.indicator_type != "DOMAIN":
                reason = "UNSUPPORTED_TYPE"

            elif not indicator_usable(indicator, now):
                reason = "EXPIRED_OR_UNUSABLE"

            elif not valid_domain(action.target_value):
                reason = "INVALID_DOMAIN"

            else:
                decision = response_decision(
                    indicator,
                    action.target_value,
                    exceptions,
                    allowed=True,
                )

                if decision.action != "BLOCK_ELIGIBLE":
                    reason = "POLICY_RECHECK_FAILED"

            if reason:
                statuses[reason] += 1
                result = "SKIP"
            else:
                statuses["ELIGIBLE"] += 1
                result = "ELIGIBLE"

            print(
                f"Action #{action.action_id}: {result}"
                f" | Current={action.execution_status}"
                f" | Reason={reason or 'Checks passed'}"
            )

    print("\n=== SUMMARY ===")
    print("Actions examined:", len(actions))
    print("Eligible:", statuses["ELIGIBLE"])
    print("Other results:", dict(statuses))
    print("Invalid staged lines:", len(invalid_lines))
    print("Database changes: NONE")
    print("E2Guardian reload: NONE")
    print("Policy changes: NONE")


if __name__ == "__main__":
    main()
