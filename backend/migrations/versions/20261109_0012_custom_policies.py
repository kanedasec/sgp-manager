"""Add owner-scoped custom JSON/YAML policy documents.

Revision ID: 20261109_0012
Revises: 20260909_0011
"""
from alembic import op
import sqlalchemy as sa


revision = "20261109_0012"
down_revision = "20260909_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "custom_policies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("format", sa.String(length=8), nullable=False),
        sa.Column("document", sa.Text(), nullable=False),
        sa.Column("parsed_document", sa.JSON(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("format IN ('json', 'yaml')", name="ck_custom_policy_format"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["owner_id"], ["owner_labels.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("owner_id", "slug", name="uq_custom_policy_owner_slug"),
    )
    op.create_index("ix_custom_policies_owner_id", "custom_policies", ["owner_id"])
    op.create_index("ix_custom_policies_slug", "custom_policies", ["slug"])


def downgrade() -> None:
    op.drop_index("ix_custom_policies_slug", table_name="custom_policies")
    op.drop_index("ix_custom_policies_owner_id", table_name="custom_policies")
    op.drop_table("custom_policies")
