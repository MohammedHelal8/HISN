"""Test approved-request preflight in a rolled-back transaction."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models.administrator import Administrator
from app.models.threat_indicator import ThreatIndicator
from app.models.blocking_action import BlockingAction
from app.models.audit_log import AuditLog
from scripts.enforcement_approved_preflight import check_approved

TEST_INDICATOR_ID = 5223

with engine.connect() as connection:
    transaction = connection.begin()
    action_id = None

    try:
        with Session(
            bind=connection,
            join_transaction_mode="create_savepoint",
        ) as db:

            admin = db.scalar(
                select(Administrator).where(
                    Administrator.role == "admin",
                    Administrator.is_active.is_(True),
                ).limit(1)
            )

            indicator = db.get(
                ThreatIndicator, TEST_INDICATOR_ID
            )

            assert admin is not None, "Active admin missing"
            assert indicator is not None, "Test indicator missing"

            action = BlockingAction(
                indicator_id=indicator.indicator_id,
                target_value=indicator.indicator_value,
                action_source="ADMIN_REQUEST",
                decision_reason="Isolated authorization preflight test",
                execution_status="APPROVED_PENDING",
                admin_id=admin.admin_id,
            )

            db.add(action)
            db.flush()
            action_id = action.action_id

            db.add(
                AuditLog(
                    admin_id=admin.admin_id,
                    action_type="ENFORCEMENT_APPROVE",
                    target_type="blocking_action",
                    target_id=str(action_id),
                    action_result="APPROVED_PENDING",
                    details="Isolated test approval",
                )
            )
            db.flush()

            print("=== APPROVED REQUEST PREFLIGHT ===")
            print("Test action:", action_id)
            print("Target:", action.target_value)
            print("Status:", action.execution_status)

            findings = check_approved(db, action)

            for finding in findings:
                print("CHECK:", finding)

            assert "NOT_ADMIN_REQUEST" not in findings
            assert "NOT_APPROVED_PENDING" not in findings
            assert "MISSING_REQUEST_ADMIN" not in findings
            assert "MISSING_APPROVAL_AUDIT" not in findings
            assert "INVALID_ACTION_STATUS" not in findings
            assert "UNEXPECTED_ACTION_SOURCE" not in findings

            print("PASS: Approved administrative state accepted")
            print("PASS: Approval audit recognized")

            if findings:
                print("RESULT: NOT AUTHORIZED")
                print("Remaining checks require resolution")
            else:
                print("RESULT: PRELIMINARY CHECKS PASSED")
                print("This is NOT permission to apply policy")

    finally:
        transaction.rollback()
        print("ROLLBACK: Temporary request and audit reverted")

if action_id is not None:
    with Session(engine) as db:
        assert db.get(BlockingAction, action_id) is None

        audits = db.scalars(
            select(AuditLog).where(
                AuditLog.target_type == "blocking_action",
                AuditLog.target_id == str(action_id),
            )
        ).all()

        assert not audits

    print("PASS: No test records persisted")

print("Policy changes: NONE")
print("E2Guardian reload: NONE")
