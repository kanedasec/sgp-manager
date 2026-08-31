"""Replace the global pipeline with reusable application gate policies.

Revision ID: 20260831_0007
Revises: 20260831_0006
"""
from uuid import UUID, uuid4

from alembic import op
import sqlalchemy as sa


revision = "20260831_0007"
down_revision = "20260831_0006"
branch_labels = None
depends_on = None


DEFAULT_POLICY_ID = UUID("00000000-0000-4000-8000-000000000007")


def upgrade() -> None:
    op.create_table(
        "gate_policies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index("ix_gate_policies_slug", "gate_policies", ["slug"], unique=True)
    op.create_table(
        "gate_policy_gates",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False),
        sa.Column("gate_id", sa.Uuid(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("blocking_severities", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.CheckConstraint("position >= 0", name="ck_gate_policy_position_nonnegative"),
        sa.ForeignKeyConstraint(["gate_id"], ["gates.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["policy_id"], ["gate_policies.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("policy_id", "gate_id", name="uq_gate_policy_gate"),
        sa.UniqueConstraint("policy_id", "position", name="uq_gate_policy_position"),
    )
    op.create_index("ix_gate_policy_gates_gate_id", "gate_policy_gates", ["gate_id"])
    op.create_index("ix_gate_policy_gates_policy_id", "gate_policy_gates", ["policy_id"])

    op.add_column("applications", sa.Column("gate_policy_id", sa.Uuid(), nullable=True))
    op.create_index("ix_applications_gate_policy_id", "applications", ["gate_policy_id"])

    bind = op.get_bind()
    gate_policies = sa.table(
        "gate_policies",
        sa.column("id", sa.Uuid()),
        sa.column("name", sa.String()),
        sa.column("slug", sa.String()),
        sa.column("description", sa.Text()),
        sa.column("active", sa.Boolean()),
    )
    policy_gates = sa.table(
        "gate_policy_gates",
        sa.column("id", sa.Uuid()),
        sa.column("policy_id", sa.Uuid()),
        sa.column("gate_id", sa.Uuid()),
        sa.column("position", sa.Integer()),
        sa.column("blocking_severities", sa.JSON()),
    )
    bind.execute(gate_policies.insert().values(
        id=DEFAULT_POLICY_ID,
        name="Default Security Policy",
        slug="default-security-policy",
        description="Migrated from the original shared security pipeline.",
        active=True,
    ))
    existing = bind.execute(sa.text(
        "SELECT id, pipeline_position, default_blocking_severities "
        "FROM gates WHERE active IS TRUE AND pipeline_position IS NOT NULL "
        "ORDER BY pipeline_position"
    )).mappings()
    for gate in existing:
        bind.execute(policy_gates.insert().values(
            id=uuid4(),
            policy_id=DEFAULT_POLICY_ID,
            gate_id=gate["id"],
            position=gate["pipeline_position"],
            blocking_severities=gate["default_blocking_severities"],
        ))

    bind.execute(
        sa.text("UPDATE applications SET gate_policy_id = :policy_id"),
        {"policy_id": DEFAULT_POLICY_ID},
    )
    op.alter_column("applications", "gate_policy_id", nullable=False)
    op.create_foreign_key(
        "fk_applications_gate_policy_id",
        "applications",
        "gate_policies",
        ["gate_policy_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    op.drop_constraint("ck_gates_pipeline_position_nonnegative", "gates", type_="check")
    op.drop_constraint("uq_gates_pipeline_position", "gates", type_="unique")
    op.drop_column("gates", "pipeline_position")


def downgrade() -> None:
    op.add_column("gates", sa.Column("pipeline_position", sa.Integer(), nullable=True))
    op.execute(
        "UPDATE gates SET pipeline_position = gate_policy_gates.position "
        "FROM gate_policy_gates WHERE gate_policy_gates.gate_id = gates.id "
        f"AND gate_policy_gates.policy_id = '{DEFAULT_POLICY_ID}'"
    )
    op.create_unique_constraint("uq_gates_pipeline_position", "gates", ["pipeline_position"])
    op.create_check_constraint(
        "ck_gates_pipeline_position_nonnegative",
        "gates",
        "pipeline_position IS NULL OR pipeline_position >= 0",
    )

    op.drop_constraint("fk_applications_gate_policy_id", "applications", type_="foreignkey")
    op.drop_index("ix_applications_gate_policy_id", table_name="applications")
    op.drop_column("applications", "gate_policy_id")
    op.drop_index("ix_gate_policy_gates_policy_id", table_name="gate_policy_gates")
    op.drop_index("ix_gate_policy_gates_gate_id", table_name="gate_policy_gates")
    op.drop_table("gate_policy_gates")
    op.drop_index("ix_gate_policies_slug", table_name="gate_policies")
    op.drop_table("gate_policies")
