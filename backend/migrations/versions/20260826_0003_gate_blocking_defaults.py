"""Clarify gate defaults as fail-closed blocking severities.

Revision ID: 20260826_0003
Revises: 20260826_0002
"""
from alembic import op
import sqlalchemy as sa


revision = "20260826_0003"
down_revision = "20260826_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "gates", "default_severities", new_column_name="default_blocking_severities",
        existing_type=sa.JSON(), existing_nullable=False,
    )
    op.execute(
        "UPDATE gates SET default_blocking_severities = "
        "'[\"low\", \"medium\", \"high\", \"critical\"]'::json "
        "WHERE json_typeof(default_blocking_severities) = 'array' "
        "AND json_array_length(default_blocking_severities) = 0"
    )
    op.alter_column(
        "gates", "default_blocking_severities", existing_type=sa.JSON(), nullable=False,
        server_default=sa.text("'[\"low\", \"medium\", \"high\", \"critical\"]'::json"),
    )


def downgrade() -> None:
    op.alter_column(
        "gates", "default_blocking_severities", new_column_name="default_severities",
        existing_type=sa.JSON(), existing_nullable=False, server_default=sa.text("'[]'::json"),
    )
