import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, Index, JSON, String, Table, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    USER = "USER"


user_group_memberships = Table(
    "user_group_memberships",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", ForeignKey("access_groups.id", ondelete="CASCADE"), primary_key=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
)


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(255), unique=True)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole, name="user_role"), default=UserRole.ADMIN)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    groups: Mapped[list["AccessGroup"]] = relationship(
        secondary=user_group_memberships, back_populates="users", lazy="selectin"
    )


class OwnerLabel(Base):
    __tablename__ = "owner_labels"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120))
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AccessGroup(Base):
    __tablename__ = "access_groups"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120))
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    users: Mapped[list[User]] = relationship(
        secondary=user_group_memberships, back_populates="groups"
    )
    permissions: Mapped[list["GroupPermission"]] = relationship(
        back_populates="group", cascade="all, delete-orphan", lazy="selectin"
    )


class GroupPermission(Base):
    __tablename__ = "group_permissions"
    __table_args__ = (
        UniqueConstraint("group_id", "resource", "action", "scope_key", name="uq_group_permission_scope"),
    )
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    group_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("access_groups.id", ondelete="CASCADE"), index=True)
    resource: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(16))
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("owner_labels.id", ondelete="RESTRICT"), index=True)
    scope_key: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    group: Mapped[AccessGroup] = relationship(back_populates="permissions")
    owner: Mapped[OwnerLabel | None] = relationship(lazy="joined")


class Application(Base):
    __tablename__ = "applications"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120))
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    policies: Mapped[list["BypassPolicy"]] = relationship(back_populates="application")


class Gate(Base):
    __tablename__ = "gates"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("owner_labels.id", ondelete="RESTRICT"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    default_blocking_severities: Mapped[list[str]] = mapped_column(
        JSON, default=lambda: ["low", "medium", "high", "critical"]
    )
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    policy_scopes: Mapped[list["BypassPolicyGate"]] = relationship(back_populates="gate")
    owner: Mapped[OwnerLabel] = relationship()


class BypassPolicy(Base):
    __tablename__ = "bypass_policies"
    __table_args__ = (Index("ix_policy_app_window", "application_id", "valid_from", "expires_at"),)
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    application_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("applications.id", ondelete="RESTRICT"), index=True)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("owner_labels.id", ondelete="RESTRICT"), index=True)
    justification: Mapped[str] = mapped_column(Text)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    revoke_reason: Mapped[str | None] = mapped_column(Text)
    application: Mapped[Application] = relationship(back_populates="policies")
    owner: Mapped[OwnerLabel] = relationship()
    gate_scopes: Mapped[list["BypassPolicyGate"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan", order_by="BypassPolicyGate.created_at"
    )
    creator: Mapped[User] = relationship(foreign_keys=[created_by])
    revoker: Mapped[User | None] = relationship(foreign_keys=[revoked_by])

    @property
    def status(self) -> str:
        now = datetime.now(UTC)
        expires = self.expires_at if self.expires_at.tzinfo else self.expires_at.replace(tzinfo=UTC)
        valid_from = self.valid_from if self.valid_from.tzinfo else self.valid_from.replace(tzinfo=UTC)
        if self.revoked_at is not None:
            return "REVOKED"
        if expires <= now:
            return "EXPIRED"
        if valid_from <= now:
            return "ACTIVE"
        return "SCHEDULED"


class BypassPolicyGate(Base):
    """One explicitly selected gate inside an auditable, application-level policy."""

    __tablename__ = "bypass_policy_gates"
    __table_args__ = (
        UniqueConstraint("policy_id", "gate_id", name="uq_policy_gate_scope"),
        Index("ix_policy_gate_app_window", "application_id", "gate_id", "valid_from", "expires_at"),
    )
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("bypass_policies.id", ondelete="CASCADE"), index=True)
    application_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("applications.id", ondelete="RESTRICT"), index=True)
    gate_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("gates.id", ondelete="RESTRICT"), index=True)
    severities: Mapped[list[str]] = mapped_column(JSON)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    policy: Mapped[BypassPolicy] = relationship(back_populates="gate_scopes")
    gate: Mapped[Gate] = relationship(back_populates="policy_scopes")


class ApiCredential(Base):
    __tablename__ = "api_credentials"
    __table_args__ = (UniqueConstraint("key_hash", name="uq_api_credentials_key_hash"),)
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120))
    key_hash: Mapped[str] = mapped_column(String(64), index=True)
    prefix: Mapped[str] = mapped_column(String(16))
    scopes: Mapped[list[str]] = mapped_column(JSON, default=lambda: ["policy:read"])
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    creator: Mapped[User] = relationship()


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    actor_type: Mapped[str] = mapped_column(String(40))
    actor_id: Mapped[str | None] = mapped_column(String(64), index=True)
    entity_type: Mapped[str | None] = mapped_column(String(80), index=True)
    entity_id: Mapped[str | None] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    event_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    source_ip: Mapped[str | None] = mapped_column(String(64))
