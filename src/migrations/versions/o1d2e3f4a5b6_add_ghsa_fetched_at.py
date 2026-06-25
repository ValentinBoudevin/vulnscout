"""add ghsa_fetched_at to vulnerabilities

Revision ID: o1d2e3f4a5b6
Revises: n0c1d2e3f4a5
Create Date: 2026-06-10 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = 'o1d2e3f4a5b6'
down_revision = 'n0c1d2e3f4a5'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.add_column(sa.Column('ghsa_fetched_at', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.drop_column('ghsa_fetched_at')
