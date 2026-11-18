"""Add an optional per-group maximum bypass duration.

Revision ID: 20261118_0015
Revises: 20261118_0014

Additive and nullable: existing groups get NULL (no limit), which is exactly
their current behavior, so no data migration is required. Older application
code ignores the column.
"""
from alembic import op
import sqlalchemy as sa


revision = "20261118_0015"
down_revision = "20261118_0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("access_groups", sa.Column("max_bypass_days", sa.Integer(), nullable=True))
    op.create_check_constraint(
        "ck_access_group_max_bypass_days",
        "access_groups",
        "max_bypass_days IS NULL OR (max_bypass_days >= 1 AND max_bypass_days <= 3650)",
    )


def downgrade() -> None:
    op.drop_constraint("ck_access_group_max_bypass_days", "access_groups", type_="check")
    op.drop_column("access_groups", "max_bypass_days")
