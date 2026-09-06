"""Add an optional finding-scope allow-list to bypass policy gate scopes.

Revision ID: 20260906_0008
Revises: 20260831_0007
"""
from alembic import op
import sqlalchemy as sa


revision = "20260906_0008"
down_revision = "20260831_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "bypass_policy_gates",
        sa.Column("finding_scope", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("bypass_policy_gates", "finding_scope")
