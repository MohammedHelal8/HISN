"""Create observed E2Guardian client activity."""
from alembic import op
import sqlalchemy as sa
revision = 'd5b24011ac09'
down_revision = 'c7e2149f3b62'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('observed_clients',
        sa.Column('client_ip', sa.String(length=45), primary_key=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('request_count', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('last_destination', sa.String(length=255), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.create_index('ix_observed_clients_last_seen', 'observed_clients', ['last_seen_at'])

def downgrade():
    op.drop_index('ix_observed_clients_last_seen', table_name='observed_clients')
    op.drop_table('observed_clients')
