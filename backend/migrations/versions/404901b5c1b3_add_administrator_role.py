
"""Add administrator role for RBAC."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# احتفظ بمعرف revision الذي أنشأه Alembic
revision: str = "404901b5c1b3"
down_revision: Union[str, Sequence[str], None] = "4620497b9361"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "administrators",
        sa.Column(
            "role",
            sa.String(length=20),
            nullable=False,
            server_default="admin",
        ),
    )

    op.create_check_constraint(
        "ck_administrators_role",
        "administrators",
        "role IN ('admin', 'viewer')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_administrators_role",
        "administrators",
        type_="check",
    )

    op.drop_column("administrators", "role")
