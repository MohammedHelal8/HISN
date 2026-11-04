"""Administrator disables for threat indicators.

Revision ID: c7e2149f3b62
Revises: 8b71c2a94e20
"""
from alembic import op
import sqlalchemy as sa

revision = "c7e2149f3b62"
down_revision = "8b71c2a94e20"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("threat_indicators", sa.Column(
        "admin_disabled", sa.Boolean(), nullable=False,
        server_default=sa.text("false"),
    ))
    op.add_column("threat_indicators", sa.Column(
        "admin_disabled_at", sa.DateTime(timezone=True), nullable=True,
    ))
    # Conservatively protect existing inactive indicators from feed reactivation.
    # Existing history cannot distinguish manual disables from other causes.
    op.execute("""UPDATE threat_indicators SET admin_disabled = true
                  WHERE source_name = 'ThreatFox' AND is_active = false""")


def downgrade():
    op.drop_column("threat_indicators", "admin_disabled_at")
    op.drop_column("threat_indicators", "admin_disabled")
