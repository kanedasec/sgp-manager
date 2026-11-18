"""Add TOML custom policies and custom policy bindings.

Revision ID: 20261118_0014
Revises: 20261111_0013

Additive only: existing custom policies keep their format, and the new
binding table starts empty, so no pipeline receives a custom policy until an
administrator explicitly binds one.
"""
from alembic import op
import sqlalchemy as sa


revision = "20261118_0014"
down_revision = "20261111_0013"
branch_labels = None
depends_on = None


BINDING_TARGET_CHECK = (
    "(target_type = 'application' AND application_id IS NOT NULL"
    " AND gate_policy_id IS NULL AND gate_id IS NULL)"
    " OR (target_type = 'gate_policy' AND gate_policy_id IS NOT NULL"
    " AND application_id IS NULL AND gate_id IS NULL)"
    " OR (target_type = 'gate' AND gate_id IS NOT NULL"
    " AND application_id IS NULL AND gate_policy_id IS NULL)"
)


def upgrade() -> None:
    op.drop_constraint("ck_custom_policy_format", "custom_policies", type_="check")
    op.create_check_constraint(
        "ck_custom_policy_format", "custom_policies", "format IN ('json', 'yaml', 'toml')",
    )
    op.create_table(
        "custom_policy_bindings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("custom_policy_id", sa.Uuid(), nullable=False),
        sa.Column("target_type", sa.String(length=16), nullable=False),
        sa.Column("application_id", sa.Uuid(), nullable=True),
        sa.Column("gate_policy_id", sa.Uuid(), nullable=True),
        sa.Column("gate_id", sa.Uuid(), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(BINDING_TARGET_CHECK, name="ck_custom_policy_binding_target"),
        sa.ForeignKeyConstraint(["custom_policy_id"], ["custom_policies.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["gate_policy_id"], ["gate_policies.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["gate_id"], ["gates.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("custom_policy_id", "application_id", name="uq_custom_policy_binding_application"),
        sa.UniqueConstraint("custom_policy_id", "gate_policy_id", name="uq_custom_policy_binding_gate_policy"),
        sa.UniqueConstraint("custom_policy_id", "gate_id", name="uq_custom_policy_binding_gate"),
    )
    op.create_index("ix_custom_policy_bindings_custom_policy_id", "custom_policy_bindings", ["custom_policy_id"])
    op.create_index("ix_custom_policy_bindings_application_id", "custom_policy_bindings", ["application_id"])
    op.create_index("ix_custom_policy_bindings_gate_policy_id", "custom_policy_bindings", ["gate_policy_id"])
    op.create_index("ix_custom_policy_bindings_gate_id", "custom_policy_bindings", ["gate_id"])


def downgrade() -> None:
    op.drop_index("ix_custom_policy_bindings_gate_id", table_name="custom_policy_bindings")
    op.drop_index("ix_custom_policy_bindings_gate_policy_id", table_name="custom_policy_bindings")
    op.drop_index("ix_custom_policy_bindings_application_id", table_name="custom_policy_bindings")
    op.drop_index("ix_custom_policy_bindings_custom_policy_id", table_name="custom_policy_bindings")
    op.drop_table("custom_policy_bindings")
    # Fails (deliberately) while TOML-authored policies exist: convert or
    # deactivate-and-migrate them before downgrading rather than losing data.
    op.drop_constraint("ck_custom_policy_format", "custom_policies", type_="check")
    op.create_check_constraint(
        "ck_custom_policy_format", "custom_policies", "format IN ('json', 'yaml')",
    )
