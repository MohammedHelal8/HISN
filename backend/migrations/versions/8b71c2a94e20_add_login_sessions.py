"""Persistent login sessions.

Revision ID: 8b71c2a94e20
Revises: 404901b5c1b3
"""
from alembic import op
import sqlalchemy as sa
revision = "8b71c2a94e20"
down_revision = "404901b5c1b3"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("login_sessions",
        sa.Column("session_id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.BigInteger(), sa.ForeignKey("administrators.admin_id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("csrf_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_login_sessions_user_id", "login_sessions", ["user_id"])
    op.create_index("ix_login_sessions_token_hash", "login_sessions", ["token_hash"], unique=True)

def downgrade():
    op.drop_index("ix_login_sessions_token_hash", table_name="login_sessions")
    op.drop_index("ix_login_sessions_user_id", table_name="login_sessions")
    op.drop_table("login_sessions")
