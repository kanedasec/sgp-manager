"""Add deterministic custom-policy selection per gate.

Revision ID: 20261119_0016
Revises: 20261118_0015

The two nullable foreign keys are additive for mixed-version rollout. A single
active, same-owner legacy gate binding has exactly the new global-fallback
meaning and is migrated. Ambiguous gate bindings and application/gate-policy
bindings are deliberately not guessed into the deterministic model.
"""
from alembic import op
import sqlalchemy as sa


revision = "20261119_0016"
down_revision = "20261118_0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "gates",
        sa.Column("custom_policy_required", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("gates", sa.Column("default_custom_policy_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_gates_default_custom_policy_id_custom_policies",
        "gates",
        "custom_policies",
        ["default_custom_policy_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "ix_gates_default_custom_policy_id", "gates", ["default_custom_policy_id"]
    )

    op.add_column(
        "gate_policy_gates", sa.Column("custom_policy_id", sa.Uuid(), nullable=True)
    )
    op.create_foreign_key(
        "fk_gate_policy_gates_custom_policy_id_custom_policies",
        "gate_policy_gates",
        "custom_policies",
        ["custom_policy_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "ix_gate_policy_gates_custom_policy_id",
        "gate_policy_gates",
        ["custom_policy_id"],
    )

    # Preserve only the legacy case that has an unambiguous equivalent: one
    # active, same-owner policy bound globally to a gate. Multiple candidates
    # and cross-owner bindings remain legacy records for explicit admin review.
    op.execute(
        """
        UPDATE gates AS gate
        SET default_custom_policy_id = candidate.custom_policy_id
        FROM (
            SELECT
                binding.gate_id,
                (array_agg(binding.custom_policy_id ORDER BY binding.created_at, binding.id))[1]
                    AS custom_policy_id
            FROM custom_policy_bindings AS binding
            JOIN custom_policies AS policy ON policy.id = binding.custom_policy_id
            JOIN gates AS bound_gate ON bound_gate.id = binding.gate_id
            WHERE binding.target_type = 'gate'
              AND binding.gate_id IS NOT NULL
              AND policy.active IS TRUE
              AND policy.owner_id = bound_gate.owner_id
            GROUP BY binding.gate_id
            HAVING count(*) = 1
        ) AS candidate
        WHERE gate.id = candidate.gate_id
          AND gate.default_custom_policy_id IS NULL
        """
    )


def downgrade() -> None:
    op.drop_index("ix_gate_policy_gates_custom_policy_id", table_name="gate_policy_gates")
    op.drop_constraint(
        "fk_gate_policy_gates_custom_policy_id_custom_policies",
        "gate_policy_gates",
        type_="foreignkey",
    )
    op.drop_column("gate_policy_gates", "custom_policy_id")

    op.drop_index("ix_gates_default_custom_policy_id", table_name="gates")
    op.drop_constraint(
        "fk_gates_default_custom_policy_id_custom_policies", "gates", type_="foreignkey"
    )
    op.drop_column("gates", "default_custom_policy_id")
    op.drop_column("gates", "custom_policy_required")
