import re
from typing import Optional

from sqlalchemy.orm import Session

from app.models import Tenant, User


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "tenant"


def make_unique_slug(db: Session, name: str) -> str:
    base = slugify(name)
    slug = base
    i = 1
    while db.query(Tenant).filter(Tenant.slug == slug).first():
        i += 1
        slug = f"{base}-{i}"
    return slug


def create_tenant(db: Session, name: str) -> Tenant:
    tenant = Tenant(name=name, slug=make_unique_slug(db, name), is_active=True)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


def get_tenant_by_id(db: Session, tenant_id: int) -> Optional[Tenant]:
    return db.query(Tenant).filter(Tenant.id == tenant_id).first()


def list_tenants(db: Session, skip: int = 0, limit: int = 100):
    return db.query(Tenant).order_by(Tenant.created_at.desc()).offset(skip).limit(limit).all()


def username_taken(db: Session, username: str) -> bool:
    return db.query(User).filter(User.username == username).first() is not None


def email_taken(db: Session, email: str) -> bool:
    return db.query(User).filter(User.email == email).first() is not None


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()


def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()


def create_user(
    db: Session, username: str, password_hash: str, tenant_id: Optional[int] = None,
    email: Optional[str] = None, role: str = "member",
) -> User:
    user = User(username=username, email=email, password_hash=password_hash, tenant_id=tenant_id, role=role, is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def list_users_in_tenant(db: Session, tenant_id: int, skip: int = 0, limit: int = 100):
    return (
        db.query(User)
        .filter(User.tenant_id == tenant_id)
        .order_by(User.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def delete_user(db: Session, user_id: int) -> bool:
    user = get_user_by_id(db, user_id)
    if not user:
        return False
    db.delete(user)
    db.commit()
    return True


def set_user_role(db: Session, user_id: int, role: str) -> Optional[User]:
    user = get_user_by_id(db, user_id)
    if user:
        user.role = role
        db.commit()
        db.refresh(user)
    return user
