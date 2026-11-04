
"""Add administrator login lockout fields.

Revision ID: 4620497b9361
Revises: 54a31ab8bc4e
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "4620497b9361"
down_revision: Union[str, Sequence[str], None] = "54a31ab8bc4e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "administrators",
        sa.Column(
            "failed_login_attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )

    op.add_column(
        "administrators",
        sa.Column(
            "locked_until",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("administrators", "locked_until")
    op.drop_column("administrators", "failed_login_attempts")
