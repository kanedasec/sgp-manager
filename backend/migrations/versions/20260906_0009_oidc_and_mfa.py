"""Add OIDC federation and TOTP MFA columns to users.

Revision ID: 20260906_0009
Revises: 20260906_0008
"""
from alembic import op
import sqlalchemy as sa


revision = "20260906_0009"
down_revision = "20260906_0008"
branch_labels = None
depends_on = None


AUTH_PROVIDER_ENUM = sa.Enum("LOCAL", "OIDC", name="auth_provider")


def upgrade() -> None:
    AUTH_PROVIDER_ENUM.create(op.get_bind(), checkfirst=True)
    op.alter_column("users", "password_hash", existing_type=sa.String(length=255), nullable=True)
    op.add_column(
        "users",
        sa.Column(
            "auth_provider", AUTH_PROVIDER_ENUM, nullable=False, server_default="LOCAL",
        ),
    )
    op.add_column("users", sa.Column("oidc_subject", sa.String(length=255), nullable=True))
    op.add_column("users", sa.Column("mfa_secret_encrypted", sa.Text(), nullable=True))
    op.add_column(
        "users", sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_users_oidc_subject", "users", ["oidc_subject"])
    op.create_unique_constraint("uq_users_oidc_subject", "users", ["oidc_subject"])


def downgrade() -> None:
    op.drop_constraint("uq_users_oidc_subject", "users", type_="unique")
    op.drop_index("ix_users_oidc_subject", table_name="users")
    op.drop_column("users", "mfa_enabled")
    op.drop_column("users", "mfa_secret_encrypted")
    op.drop_column("users", "oidc_subject")
    op.drop_column("users", "auth_provider")
    op.alter_column("users", "password_hash", existing_type=sa.String(length=255), nullable=False)
    AUTH_PROVIDER_ENUM.drop(op.get_bind(), checkfirst=True)
