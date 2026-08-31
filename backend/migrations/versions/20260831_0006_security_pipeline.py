"""Add an ordered global security pipeline.

Revision ID: 20260831_0006
Revises: 20260827_0005
"""
from alembic import op
import sqlalchemy as sa


revision = "20260831_0006"
down_revision = "20260827_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("gates", sa.Column("pipeline_position", sa.Integer(), nullable=True))
    op.execute(
        "WITH ranked AS ("
        "SELECT id, row_number() OVER (ORDER BY CASE slug "
        "WHEN 'sast' THEN 0 WHEN 'secrets' THEN 1 WHEN 'sca' THEN 2 END) - 1 AS position "
        "FROM gates WHERE active IS TRUE AND slug IN ('sast', 'secrets', 'sca')"
        ") UPDATE gates SET pipeline_position = ranked.position "
        "FROM ranked WHERE gates.id = ranked.id"
    )
    op.create_unique_constraint(
        "uq_gates_pipeline_position", "gates", ["pipeline_position"]
    )
    op.create_check_constraint(
        "ck_gates_pipeline_position_nonnegative",
        "gates",
        "pipeline_position IS NULL OR pipeline_position >= 0",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_gates_pipeline_position_nonnegative", "gates", type_="check"
    )
    op.drop_constraint("uq_gates_pipeline_position", "gates", type_="unique")
    op.drop_column("gates", "pipeline_position")
