"""Test post-approval invalidation. All DB changes are rolled back."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models.administrator import Administrator
from app.models.threat_indicator import ThreatIndicator
from app.models.blocking_action import BlockingAction
from app.models.blocking_exception import BlockingException
from app.models.audit_log import AuditLog
from app.security_engine.detection import exception_matches
from scripts.enforcement_approved_preflight import check_approved

INDICATOR_ID = 5223

with engine.connect() as connection:
    transaction = connection.begin()

    try:
        with Session(
            bind=connection,
            join_transaction_mode="create_savepoint",
        ) as db:
            admin = db.scalar(
                select(Administrator)
                .where(
                    Administrator.role == "admin",
                    Administrator.is_active.is_(True),
                )
                .limit(1)
            )
            indicator = db.get(ThreatIndicator, INDICATOR_ID)

            assert admin is not None
            assert indicator is not None
            assert indicator.confidence_level == "HIGH"
            assert indicator.is_active
            assert not indicator.admin_disabled

            target = indicator.indicator_value

            existing_exceptions = db.scalars(
                select(BlockingException)
            ).all()

            assert not exception_matches(
                target, existing_exceptions
            ), "Target already has a HISN exception"

            action = BlockingAction(
                indicator_id=indicator.indicator_id,
                target_value=target,
                action_source="ADMIN_REQUEST",
                decision_reason="Revalidation security test",
                execution_status="APPROVED_PENDING",
                admin_id=admin.admin_id,
            )

            db.add(action)
            db.flush()

            db.add(
                AuditLog(
                    admin_id=admin.admin_id,
                    action_type="ENFORCEMENT_APPROVE",
                    target_type="blocking_action",
                    target_id=str(action.action_id),
                    action_result="APPROVED_PENDING",
                    details="Temporary approval test",
                )
            )
            db.flush()

            print("=== BASELINE ===")
            baseline = check_approved(db, action)
            print("Findings:", baseline)

            assert "MISSING_APPROVAL_AUDIT" not in baseline
            assert "INVALID_ACTION_STATUS" not in baseline

            print("PASS: Approval state recognized")

            print("\n=== ADMINISTRATIVE DISABLE ===")

            indicator.admin_disabled = True
            db.flush()

            disabled_findings = check_approved(db, action)
            print("Findings:", disabled_findings)

            assert "INDICATOR_NOT_USABLE" in disabled_findings
            print("PASS: Disabled indicator prevents authorization")

            indicator.admin_disabled = False
            db.flush()

            print("\n=== NEW EXCEPTION AFTER APPROVAL ===")

            new_exception = BlockingException(
                target_type="DOMAIN",
                target_value=target,
                created_by=admin.admin_id,
            )

            db.add(new_exception)
            db.flush()

            exception_findings = check_approved(db, action)
            print("Findings:", exception_findings)

            assert "RESPONSE_DECISION_EXCEPTION" in exception_findings
            print("PASS: New exception prevents authorization")

    finally:
        transaction.rollback()
        print("\nROLLBACK: All test database changes reverted")

print("SUCCESS: Post-approval revalidation passed")
print("E2Guardian policy changes: NONE")
print("E2Guardian reload: NONE")
