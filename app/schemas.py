from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    """Self-service signup: creates a brand new tenant (company) and its
    first user, who becomes that tenant's 'owner'."""
    tenant_name: str = Field(..., min_length=2, max_length=255, examples=["Acme Corp"])
    username: str = Field(..., min_length=3, max_length=64)
    email: Optional[EmailStr] = None
    password: str = Field(..., min_length=8)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class TenantOut(BaseModel):
    id: int
    name: str
    slug: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TenantCreate(BaseModel):
    """Platform-level: creates a tenant plus its first owner user in one call."""
    tenant_name: str = Field(..., min_length=2, max_length=255)
    owner_username: str = Field(..., min_length=3, max_length=64)
    owner_email: Optional[EmailStr] = None
    owner_password: Optional[str] = Field(None, min_length=8, description="Omit to auto-generate one.")


class UserOut(BaseModel):
    id: int
    tenant_id: Optional[int] = None
    username: str
    email: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    generated_password: Optional[str] = Field(None, description="Only present once, right after creation, if no password was supplied.")

    model_config = {"from_attributes": True}


class UserCreateInTenant(BaseModel):
    """Adding a member to an existing tenant."""
    username: str = Field(..., min_length=3, max_length=64)
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8, description="Omit to auto-generate one.")
    role: str = Field("member", description="member or admin. Only an owner/admin can set role='admin'.")


class MeOut(BaseModel):
    user_id: int
    username: str
    tenant_id: Optional[int]
    role: str
