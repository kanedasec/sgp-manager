"""Add owner-scoped groups and RBAC permissions.

Revision ID: 20260826_0004
Revises: 20260826_0003
"""
from alembic import op
import sqlalchemy as sa


revision = "20260826_0004"
down_revision = "20260826_0003"
branch_labels = None
depends_on = None

UNASSIGNED_OWNER_ID = "00000000-0000-0000-0000-000000000001"


def upgrade() -> None:
    op.execute("ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'USER'")
    op.create_table(
        "owner_labels",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_owner_labels_slug", "owner_labels", ["slug"], unique=True)
    op.execute(
        "INSERT INTO owner_labels (id, name, slug, description, active, created_at, updated_at) VALUES "
        f"('{UNASSIGNED_OWNER_ID}'::uuid, 'Unassigned', 'unassigned', "
        "'Migration owner for gates and policies created before owner-scoped RBAC.', true, now(), now())"
    )

    for table in ("gates", "bypass_policies"):
        op.add_column(table, sa.Column("owner_id", sa.Uuid(), nullable=True))
        op.execute(f"UPDATE {table} SET owner_id = '{UNASSIGNED_OWNER_ID}'::uuid")
        op.alter_column(table, "owner_id", nullable=False)
        op.create_foreign_key(
            f"{table}_owner_id_fkey", table, "owner_labels", ["owner_id"], ["id"], ondelete="RESTRICT"
        )
        op.create_index(f"ix_{table}_owner_id", table, ["owner_id"])

    op.create_table(
        "access_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_access_groups_slug", "access_groups", ["slug"], unique=True)
    op.create_table(
        "group_permissions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.Column("resource", sa.String(32), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("owner_id", sa.Uuid()),
        sa.Column("scope_key", sa.String(40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["group_id"], ["access_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_id"], ["owner_labels.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("group_id", "resource", "action", "scope_key", name="uq_group_permission_scope"),
    )
    op.create_index("ix_group_permissions_group_id", "group_permissions", ["group_id"])
    op.create_index("ix_group_permissions_owner_id", "group_permissions", ["owner_id"])
    op.create_table(
        "user_group_memberships",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["group_id"], ["access_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "group_id"),
    )


def downgrade() -> None:
    op.drop_table("user_group_memberships")
    op.drop_table("group_permissions")
    op.drop_table("access_groups")
    for table in ("bypass_policies", "gates"):
        op.drop_index(f"ix_{table}_owner_id", table_name=table)
        op.drop_constraint(f"{table}_owner_id_fkey", table, type_="foreignkey")
        op.drop_column(table, "owner_id")
    op.drop_table("owner_labels")
    # PostgreSQL enum values are intentionally retained; removing one requires rebuilding the enum type.
