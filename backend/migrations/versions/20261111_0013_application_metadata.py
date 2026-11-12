"""Add owner, company, and criticality metadata to applications.

Revision ID: 20261111_0013
Revises: 20261109_0012
"""
from alembic import op
import sqlalchemy as sa


revision = "20261111_0013"
down_revision = "20261109_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("applications", sa.Column("owner_id", sa.Uuid(), nullable=True))
    op.add_column("applications", sa.Column("company", sa.String(length=120), nullable=True))
    op.add_column("applications", sa.Column("criticality", sa.String(length=16), nullable=True))
    op.create_foreign_key(
        "fk_applications_owner_id_owner_labels",
        "applications", "owner_labels", ["owner_id"], ["id"], ondelete="RESTRICT",
    )
    op.create_index("ix_applications_owner_id", "applications", ["owner_id"])
    op.create_check_constraint(
        "ck_application_criticality",
        "applications",
        "criticality IS NULL OR criticality IN ('low', 'medium', 'high', 'critical')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_application_criticality", "applications", type_="check")
    op.drop_index("ix_applications_owner_id", table_name="applications")
    op.drop_constraint("fk_applications_owner_id_owner_labels", "applications", type_="foreignkey")
    op.drop_column("applications", "criticality")
    op.drop_column("applications", "company")
    op.drop_column("applications", "owner_id")
