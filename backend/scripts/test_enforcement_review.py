"""Isolated approval/rejection workflow test; no policy writes."""

from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.main import app
from app.core.database import engine, get_db
from app.core.auth_dependencies import get_current_user
from app.models.administrator import Administrator
from app.models.threat_indicator import ThreatIndicator
from app.models.blocking_action import BlockingAction
from app.models.audit_log import AuditLog
from app.security_engine.detection import indicator_usable

BASE = "/api/security/enforcement/requests"
TEST_INDICATOR_ID = 5223
created_ids = []

with engine.connect() as connection:
    outer = connection.begin()

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

            indicator = db.get(
                ThreatIndicator, TEST_INDICATOR_ID
            )

            assert admin is not None, "No active admin found"
            assert indicator is not None, "Test indicator missing"
            assert indicator_usable(indicator)
            assert indicator.confidence_level == "HIGH"
            assert indicator.indicator_type == "DOMAIN"

            admin_id = admin.admin_id
            target = indicator.indicator_value

        def mock_admin():
            return SimpleNamespace(
                admin_id=admin_id,
                role="admin",
                is_active=True,
            )

        def test_db():
            with Session(
                bind=connection,
                join_transaction_mode="create_savepoint",
            ) as db:
                yield db

        app.dependency_overrides[get_current_user] = mock_admin
        app.dependency_overrides[get_db] = test_db

        try:
            with TestClient(
                app,
                base_url="http://127.0.0.1:8000",
            ) as client:

                def create_request(label):
                    response = client.post(
                        BASE,
                        json={
                            "indicator_id": TEST_INDICATOR_ID,
                            "target_value": target,
                            "reason": label,
                        },
                    )

                    print("CREATE:", response.status_code)
                    print("BODY:", response.text[:350])
                    assert response.status_code == 201

                    action_id = response.json()["action_id"]
                    created_ids.append(action_id)
                    return action_id

                print("=== APPROVAL TEST ===")
                approved_id = create_request(
                    "Isolated approval workflow test"
                )

                response = client.post(
                    f"{BASE}/{approved_id}/approve",
                    json={
                        "reason": "Approved for isolated testing"
                    },
                )

                print("APPROVE:", response.status_code)
                print("BODY:", response.text[:350])

                assert response.status_code == 200
                assert (
                    response.json()["execution_status"]
                    == "APPROVED_PENDING"
                )
                assert response.json()["policy_applied"] is False

                # A reviewed request cannot be reviewed again.
                duplicate = client.post(
                    f"{BASE}/{approved_id}/approve",
                    json={"reason": "Duplicate approval test"},
                )

                assert duplicate.status_code == 409
                print("PASS: Duplicate approval rejected")

                print("\n=== REJECTION TEST ===")
                rejected_id = create_request(
                    "Isolated rejection workflow test"
                )

                response = client.post(
                    f"{BASE}/{rejected_id}/reject",
                    json={
                        "reason": "Rejected for isolated testing"
                    },
                )

                print("REJECT:", response.status_code)
                print("BODY:", response.text[:350])

                assert response.status_code == 200
                assert (
                    response.json()["execution_status"]
                    == "REJECTED"
                )

                # Rejected requests cannot later be approved.
                repeated = client.post(
                    f"{BASE}/{rejected_id}/approve",
                    json={"reason": "Approval after rejection test"},
                )

                assert repeated.status_code == 409
                print("PASS: Approval after rejection rejected")

        finally:
            app.dependency_overrides.pop(
                get_current_user, None
            )
            app.dependency_overrides.pop(get_db, None)

        print("\n=== DATABASE VERIFICATION ===")

        with Session(
            bind=connection,
            join_transaction_mode="create_savepoint",
        ) as db:

            expected = {
                approved_id: (
                    "APPROVED_PENDING",
                    "ENFORCEMENT_APPROVE",
                ),
                rejected_id: (
                    "REJECTED",
                    "ENFORCEMENT_REJECT",
                ),
            }

            for action_id, (status, audit_type) in expected.items():
                action = db.get(BlockingAction, action_id)

                assert action is not None
                assert action.execution_status == status
                assert action.admin_id == admin_id
                assert action.executed_at is None
                assert action.verified_at is None

                audits = db.scalars(
                    select(AuditLog).where(
                        AuditLog.target_type == "blocking_action",
                        AuditLog.target_id == str(action_id),
                    )
                ).all()

                audit_types = {row.action_type for row in audits}

                assert "ENFORCEMENT_REQUEST" in audit_types
                assert audit_type in audit_types
                assert len(audits) == 2

                print(
                    f"PASS: Action #{action_id} -> {status}"
                )
                print(
                    f"PASS: Request + review audit recorded"
                )

    finally:
        outer.rollback()
        print("\nROLLBACK: Test transaction reverted")

if created_ids:
    with Session(engine) as db:
        for action_id in created_ids:
            assert db.get(BlockingAction, action_id) is None

            audits = db.scalars(
                select(AuditLog).where(
                    AuditLog.target_type == "blocking_action",
                    AuditLog.target_id == str(action_id),
                )
            ).all()

            assert len(audits) == 0

    print("PASS: No test actions or audit records persisted")

print("SUCCESS: Approval/rejection workflow tests passed")
print("E2Guardian policy changes: NONE")
print("E2Guardian reload: NONE")
