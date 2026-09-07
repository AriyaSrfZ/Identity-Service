"""
Managing members WITHIN a tenant. An owner/admin manages their own
tenant's users here; a platform admin/API key can also act on any
tenant by passing its tenant_id explicitly.
"""

import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app import crud
from app.security import hash_password
from app.schemas import UserCreateInTenant, UserOut
from app.deps import require_tenant_role, Claims

router = APIRouter(prefix="/tenants/{tenant_id}/users", tags=["users"])


def _check_tenant_access(claims: Claims, tenant_id: int):
    """A non-platform caller can only act on their own tenant."""
    if not claims.is_super_admin and claims.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Tenant not found")  # don't confirm existence of other tenants


@router.post(
    "",
    response_model=UserOut,
    summary="Add a member to a tenant",
    description="Requires role 'admin' or 'owner' within the tenant (or platform admin/API key). Omit password to auto-generate one.",
    responses={400: {"description": "Username/email already taken"}, 403: {"description": "Insufficient role"}},
)
def create_tenant_user(
    tenant_id: int,
    payload: UserCreateInTenant,
    db: Session = Depends(get_db),
    claims: Claims = Depends(require_tenant_role("admin")),
):
    _check_tenant_access(claims, tenant_id)
    if not crud.get_tenant_by_id(db, tenant_id):
        raise HTTPException(status_code=404, detail="Tenant not found")
    if payload.role not in ("member", "admin"):
        raise HTTPException(status_code=400, detail="role must be 'member' or 'admin'.")
    if crud.username_taken(db, payload.username):
        raise HTTPException(status_code=400, detail="That username is already taken.")
    if payload.email and crud.email_taken(db, payload.email):
        raise HTTPException(status_code=400, detail="That email is already registered.")

    generated_password = None
    plain = payload.password
    if not plain:
        generated_password = secrets.token_urlsafe(12)
        plain = generated_password

    user = crud.create_user(
        db, username=payload.username, password_hash=hash_password(plain),
        tenant_id=tenant_id, email=payload.email, role=payload.role,
    )
    return UserOut(
        id=user.id, tenant_id=user.tenant_id, username=user.username, email=user.email,
        role=user.role, is_active=user.is_active, created_at=user.created_at,
        generated_password=generated_password,
    )


@router.get("", response_model=list[UserOut], summary="List members of a tenant")
def list_tenant_users(tenant_id: int, db: Session = Depends(get_db), claims: Claims = Depends(require_tenant_role("member"))):
    _check_tenant_access(claims, tenant_id)
    users = crud.list_users_in_tenant(db, tenant_id)
    return [UserOut(id=u.id, tenant_id=u.tenant_id, username=u.username, email=u.email, role=u.role, is_active=u.is_active, created_at=u.created_at) for u in users]


@router.delete("/{user_id}", summary="Remove a member from a tenant")
def delete_tenant_user(tenant_id: int, user_id: int, db: Session = Depends(get_db), claims: Claims = Depends(require_tenant_role("admin"))):
    _check_tenant_access(claims, tenant_id)
    user = crud.get_user_by_id(db, user_id)
    if not user or user.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="User not found in this tenant")
    if user.role == "owner":
        raise HTTPException(status_code=400, detail="Cannot delete the tenant owner.")
    crud.delete_user(db, user_id)
    return {"ok": True}
