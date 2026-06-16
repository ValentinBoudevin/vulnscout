"""add epss_data_updated_at and ghsa_data_updated_at to vulnerabilities

Revision ID: p2e3f4a5b6c7
Revises: o1d2e3f4a5b6
Create Date: 2026-06-15 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = 'p2e3f4a5b6c7'
down_revision = 'o1d2e3f4a5b6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.add_column(sa.Column('epss_data_updated_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('ghsa_data_updated_at', sa.DateTime(), nullable=True))

    # Backfill so existing rows don't show "Never" for Updated when data is present.
    op.execute(
        "UPDATE vulnerabilities SET epss_data_updated_at = epss_fetched_at "
        "WHERE epss_score IS NOT NULL AND epss_fetched_at IS NOT NULL"
    )
    op.execute(
        "UPDATE vulnerabilities SET ghsa_data_updated_at = ghsa_fetched_at "
        "WHERE publish_date IS NOT NULL AND ghsa_fetched_at IS NOT NULL"
    )


def downgrade():
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.drop_column('ghsa_data_updated_at')
        batch_op.drop_column('epss_data_updated_at')
