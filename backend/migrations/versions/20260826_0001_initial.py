"""Initial security gate bypass manager schema."""
from alembic import op
import sqlalchemy as sa


revision = "20260826_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS btree_gist")
    user_role = sa.Enum("ADMIN", name="user_role")
    op.create_table(
        "users", sa.Column("id", sa.Uuid(), nullable=False), sa.Column("username", sa.String(64), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False), sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("email", sa.String(255), nullable=False), sa.Column("role", user_role, nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    for table in ("applications", "gates"):
        op.create_table(
            table, sa.Column("id", sa.Uuid(), nullable=False), sa.Column("name", sa.String(120), nullable=False),
            sa.Column("slug", sa.String(100), nullable=False), sa.Column("description", sa.Text()),
            sa.Column("active", sa.Boolean(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(f"ix_{table}_slug", table, ["slug"], unique=True)
    op.create_table(
        "bypass_policies", sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("application_id", sa.Uuid(), nullable=False), sa.Column("gate_id", sa.Uuid(), nullable=False),
        sa.Column("severities", sa.JSON(), nullable=False), sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_by", sa.Uuid()), sa.Column("revoke_reason", sa.Text()), sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["gate_id"], ["gates.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["revoked_by"], ["users.id"], ondelete="RESTRICT"),
    )
    op.create_index("ix_bypass_policies_application_id", "bypass_policies", ["application_id"])
    op.create_index("ix_bypass_policies_gate_id", "bypass_policies", ["gate_id"])
    op.create_index("ix_bypass_policies_expires_at", "bypass_policies", ["expires_at"])
    op.create_index("ix_policy_app_gate_window", "bypass_policies", ["application_id", "gate_id", "valid_from", "expires_at"])
    op.execute(
        "ALTER TABLE bypass_policies ADD CONSTRAINT no_overlapping_policy_windows "
        "EXCLUDE USING gist (application_id WITH =, gate_id WITH =, "
        "tstzrange(valid_from, expires_at, '[)') WITH &&) WHERE (revoked_at IS NULL)"
    )
    op.create_table(
        "api_credentials", sa.Column("id", sa.Uuid(), nullable=False), sa.Column("name", sa.String(120), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False), sa.Column("prefix", sa.String(16), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False), sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)), sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id"), sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("key_hash", name="uq_api_credentials_key_hash"),
    )
    op.create_index("ix_api_credentials_key_hash", "api_credentials", ["key_hash"])
    op.create_table(
        "audit_logs", sa.Column("id", sa.Uuid(), nullable=False), sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("actor_type", sa.String(40), nullable=False), sa.Column("actor_id", sa.String(64)),
        sa.Column("entity_type", sa.String(80)), sa.Column("entity_id", sa.String(64)),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False), sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("source_ip", sa.String(64)), sa.PrimaryKeyConstraint("id"),
    )
    for column in ("event_type", "actor_id", "entity_type", "entity_id", "timestamp"):
        op.create_index(f"ix_audit_logs_{column}", "audit_logs", [column])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("api_credentials")
    op.drop_table("bypass_policies")
    op.drop_table("gates")
    op.drop_table("applications")
    op.drop_table("users")
    sa.Enum(name="user_role").drop(op.get_bind(), checkfirst=True)
