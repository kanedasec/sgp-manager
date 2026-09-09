"""Add credential_version to users for stale-session invalidation.

Revision ID: 20260909_0011
Revises: 20260907_0010
"""
from alembic import op
import sqlalchemy as sa


revision = "20260909_0011"
down_revision = "20260907_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("credential_version", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("users", "credential_version")
