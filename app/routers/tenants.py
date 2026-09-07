"""
Platform-level tenant management. Only a platform super_admin or the
platform API key can call these - a tenant's own owner/admin manages
their members via routers/users.py instead, not this file.
"""

import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app import crud
from app.security import hash_password
from app.schemas import TenantCreate, TenantOut, UserOut
from app.deps import require_platform_admin, Claims

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.post(
    "",
    response_model=UserOut,
    summary="Provision a new tenant plus its first owner user, in one call",
    description=(
        "Platform admin / API key only. Use this when your own app/panel "
        "needs to create a tenant automatically (e.g. a new customer signs "
        "up in your product, and you want a matching tenant here)."
    ),
    responses={400: {"description": "owner_username or owner_email already taken"}},
)
def create_tenant(payload: TenantCreate, db: Session = Depends(get_db), _: Claims = Depends(require_platform_admin)):
    if crud.username_taken(db, payload.owner_username):
        raise HTTPException(status_code=400, detail="That username is already taken.")
    if payload.owner_email and crud.email_taken(db, payload.owner_email):
        raise HTTPException(status_code=400, detail="That email is already registered.")

    tenant = crud.create_tenant(db, name=payload.tenant_name)

    generated_password = None
    plain = payload.owner_password
    if not plain:
        generated_password = secrets.token_urlsafe(12)
        plain = generated_password

    user = crud.create_user(
        db, username=payload.owner_username, password_hash=hash_password(plain),
        tenant_id=tenant.id, email=payload.owner_email, role="owner",
    )
    return UserOut(
        id=user.id, tenant_id=user.tenant_id, username=user.username, email=user.email,
        role=user.role, is_active=user.is_active, created_at=user.created_at,
        generated_password=generated_password,
    )


@router.get("", response_model=list[TenantOut], summary="List all tenants")
def list_tenants(db: Session = Depends(get_db), _: Claims = Depends(require_platform_admin)):
    return crud.list_tenants(db)


@router.get("/{tenant_id}", response_model=TenantOut)
def get_tenant(tenant_id: int, db: Session = Depends(get_db), _: Claims = Depends(require_platform_admin)):
    tenant = crud.get_tenant_by_id(db, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant
