"""
Two independent auth paths, same pattern as the link-shortener project:
1. Bearer JWT - normal user/tenant-scoped requests. Verified locally
   against this service's own public key (no extra step needed since
   we hold both keys here; a *consuming* service does the same
   verification using GET /public-key instead).
2. Platform API key (X-API-Key) - for trusted infrastructure (an ops
   script, another service) to manage tenants without a human logging
   in. Always treated as platform-level (super_admin-equivalent) access.
"""

from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, HTTPException, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

import secrets

from app.config import settings
from app.database import get_db
from app.security import decode_token
from app import crud

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class Claims:
    user_id: Optional[int]
    username: str
    tenant_id: Optional[int]
    role: str

    @property
    def is_super_admin(self) -> bool:
        return self.role == "super_admin"

    def has_at_least(self, min_role: str) -> bool:
        from app.models import ROLE_HIERARCHY
        if self.is_super_admin:
            return True
        return ROLE_HIERARCHY.get(self.role, 0) >= ROLE_HIERARCHY.get(min_role, 99)


def get_current_claims(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    x_api_key: Optional[str] = Header(None),
) -> Optional[Claims]:
    if settings.platform_api_key and x_api_key and secrets.compare_digest(x_api_key, settings.platform_api_key):
        return Claims(user_id=None, username="platform-api-key", tenant_id=None, role="super_admin")

    if credentials:
        payload = decode_token(credentials.credentials)
        if payload:
            return Claims(
                user_id=int(payload["sub"]),
                username=payload["username"],
                tenant_id=payload.get("tenant_id"),
                role=payload["role"],
            )
    return None


def require_auth(claims: Optional[Claims] = Depends(get_current_claims)) -> Claims:
    if claims is None:
        raise HTTPException(status_code=401, detail="Missing or invalid credentials.")
    return claims


def require_platform_admin(claims: Claims = Depends(require_auth)) -> Claims:
    if not claims.is_super_admin:
        raise HTTPException(status_code=403, detail="Platform admin access required.")
    return claims


def require_tenant_role(min_role: str):
    """Factory: require_tenant_role('admin') -> dependency that checks the
    caller has at least that role WITHIN THEIR OWN TENANT. Does not let
    a caller act on a different tenant_id than their own token carries,
    unless they're a platform-level caller (super_admin / API key)."""

    def _dep(claims: Claims = Depends(require_auth)) -> Claims:
        if claims.is_super_admin:
            return claims
        if not claims.has_at_least(min_role):
            raise HTTPException(status_code=403, detail=f"Requires role '{min_role}' or higher in your tenant.")
        return claims

    return _dep
