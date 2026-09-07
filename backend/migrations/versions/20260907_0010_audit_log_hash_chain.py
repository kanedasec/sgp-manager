"""Add tamper-evident hash chain columns to audit_logs.

Revision ID: 20260907_0010
Revises: 20260906_0009
"""
from alembic import op
import sqlalchemy as sa


revision = "20260907_0010"
down_revision = "20260906_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("sequence", sa.BigInteger(), nullable=True))
    op.add_column("audit_logs", sa.Column("prev_hash", sa.String(length=64), nullable=True))
    op.add_column("audit_logs", sa.Column("entry_hash", sa.String(length=64), nullable=True))
    op.create_unique_constraint("uq_audit_logs_sequence", "audit_logs", ["sequence"])
    # Existing rows predate the hash chain and are intentionally left with
    # NULL sequence/prev_hash/entry_hash: verify_chain() only walks hashed
    # rows, so pre-existing history is neither falsely flagged as broken
    # nor silently included in a chain it was never actually part of.


def downgrade() -> None:
    op.drop_constraint("uq_audit_logs_sequence", "audit_logs", type_="unique")
    op.drop_column("audit_logs", "entry_hash")
    op.drop_column("audit_logs", "prev_hash")
    op.drop_column("audit_logs", "sequence")
