"""Require bootstrap administrators to replace their initial password.

Revision ID: 20260827_0005
Revises: 20260826_0004
"""
from alembic import op
import sqlalchemy as sa


revision = "20260827_0005"
down_revision = "20260826_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.alter_column("users", "must_change_password", server_default=None)


def downgrade() -> None:
    op.drop_column("users", "must_change_password")
