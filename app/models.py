"""
Tenant: one customer organization. Everything else in a consuming app
(links, QR codes, whatever) gets tagged with a tenant_id, not a user_id -
so a whole company's data stays grouped even as individual users come
and go within it.

User: belongs to exactly one tenant (or none, for a platform super_admin
who manages tenants themselves, not any tenant's data). Role is scoped
to that tenant: owner > admin > member. A platform super_admin sits
outside this hierarchy entirely.
"""

from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship

from app.database import Base

ROLE_HIERARCHY = {"member": 1, "admin": 2, "owner": 3}


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, index=True, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)  # null = platform super_admin
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="member", nullable=False)  # owner/admin/member, or super_admin
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    tenant = relationship("Tenant", back_populates="users")

    @property
    def is_super_admin(self) -> bool:
        return self.role == "super_admin"

    def has_at_least(self, min_role: str) -> bool:
        """Role check within a tenant, e.g. user.has_at_least('admin')."""
        if self.is_super_admin:
            return True
        return ROLE_HIERARCHY.get(self.role, 0) >= ROLE_HIERARCHY.get(min_role, 99)
