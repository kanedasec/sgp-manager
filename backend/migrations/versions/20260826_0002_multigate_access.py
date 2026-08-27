"""Group multiple gate scopes in one policy and add gate defaults.

Revision ID: 20260826_0002
Revises: 20260826_0001
"""
from alembic import op
import sqlalchemy as sa


revision = "20260826_0002"
down_revision = "20260826_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "gates",
        sa.Column("default_severities", sa.JSON(), nullable=False, server_default=sa.text("'[]'::json")),
    )
    op.create_table(
        "bypass_policy_gates",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False),
        sa.Column("application_id", sa.Uuid(), nullable=False),
        sa.Column("gate_id", sa.Uuid(), nullable=False),
        sa.Column("severities", sa.JSON(), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["gate_id"], ["gates.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["policy_id"], ["bypass_policies.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("policy_id", "gate_id", name="uq_policy_gate_scope"),
    )
    op.execute(
        "INSERT INTO bypass_policy_gates "
        "(id, policy_id, application_id, gate_id, severities, valid_from, expires_at, revoked_at, created_at) "
        "SELECT md5(id::text || gate_id::text)::uuid, id, application_id, gate_id, severities, "
        "valid_from, expires_at, revoked_at, created_at FROM bypass_policies"
    )
    op.create_index("ix_bypass_policy_gates_policy_id", "bypass_policy_gates", ["policy_id"])
    op.create_index("ix_bypass_policy_gates_application_id", "bypass_policy_gates", ["application_id"])
    op.create_index("ix_bypass_policy_gates_gate_id", "bypass_policy_gates", ["gate_id"])
    op.create_index("ix_bypass_policy_gates_expires_at", "bypass_policy_gates", ["expires_at"])
    op.create_index(
        "ix_policy_gate_app_window", "bypass_policy_gates",
        ["application_id", "gate_id", "valid_from", "expires_at"],
    )
    op.execute(
        "ALTER TABLE bypass_policy_gates ADD CONSTRAINT no_overlapping_policy_gate_windows "
        "EXCLUDE USING gist (application_id WITH =, gate_id WITH =, "
        "tstzrange(valid_from, expires_at, '[)') WITH &&) WHERE (revoked_at IS NULL)"
    )

    op.execute("ALTER TABLE bypass_policies DROP CONSTRAINT no_overlapping_policy_windows")
    op.drop_index("ix_policy_app_gate_window", table_name="bypass_policies")
    op.drop_index("ix_bypass_policies_gate_id", table_name="bypass_policies")
    op.drop_constraint("bypass_policies_gate_id_fkey", "bypass_policies", type_="foreignkey")
    op.drop_column("bypass_policies", "gate_id")
    op.drop_column("bypass_policies", "severities")
    op.create_index("ix_policy_app_window", "bypass_policies", ["application_id", "valid_from", "expires_at"])


def downgrade() -> None:
    op.add_column("bypass_policies", sa.Column("severities", sa.JSON(), nullable=True))
    op.add_column("bypass_policies", sa.Column("gate_id", sa.Uuid(), nullable=True))
    op.execute(
        "UPDATE bypass_policies p SET gate_id = s.gate_id, severities = s.severities "
        "FROM (SELECT DISTINCT ON (policy_id) policy_id, gate_id, severities "
        "FROM bypass_policy_gates ORDER BY policy_id, created_at) s WHERE p.id = s.policy_id"
    )
    op.alter_column("bypass_policies", "gate_id", nullable=False)
    op.alter_column("bypass_policies", "severities", nullable=False)
    op.create_foreign_key(
        "bypass_policies_gate_id_fkey", "bypass_policies", "gates", ["gate_id"], ["id"], ondelete="RESTRICT"
    )
    op.create_index("ix_bypass_policies_gate_id", "bypass_policies", ["gate_id"])
    op.create_index(
        "ix_policy_app_gate_window", "bypass_policies", ["application_id", "gate_id", "valid_from", "expires_at"]
    )
    op.execute(
        "ALTER TABLE bypass_policies ADD CONSTRAINT no_overlapping_policy_windows "
        "EXCLUDE USING gist (application_id WITH =, gate_id WITH =, "
        "tstzrange(valid_from, expires_at, '[)') WITH &&) WHERE (revoked_at IS NULL)"
    )
    op.drop_index("ix_policy_app_window", table_name="bypass_policies")
    op.drop_table("bypass_policy_gates")
    op.drop_column("gates", "default_severities")
