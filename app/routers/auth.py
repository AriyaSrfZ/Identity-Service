from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import get_db
from app.config import settings
from app import crud
from app.security import hash_password, verify_password, create_access_token, get_public_key_pem, DUMMY_BCRYPT_HASH
from app.schemas import RegisterRequest, LoginRequest, TokenResponse, MeOut
from app.deps import require_auth, Claims

limiter = Limiter(key_func=get_remote_address)
router = APIRouter(tags=["auth"])


@router.post(
    "/auth/register",
    response_model=TokenResponse,
    summary="Self-service signup: creates a new tenant (company) and its first user (role=owner)",
    responses={400: {"description": "Username/email already taken"}},
)
@limiter.limit(settings.rate_limit_register)
def register(request: Request, payload: RegisterRequest, db: Session = Depends(get_db)):
    if crud.username_taken(db, payload.username):
        raise HTTPException(status_code=400, detail="That username is already taken.")
    if payload.email and crud.email_taken(db, payload.email):
        raise HTTPException(status_code=400, detail="That email is already registered.")

    tenant = crud.create_tenant(db, name=payload.tenant_name)
    user = crud.create_user(
        db, username=payload.username, password_hash=hash_password(payload.password),
        tenant_id=tenant.id, email=payload.email, role="owner",
    )
    token = create_access_token(user)
    return TokenResponse(access_token=token, expires_in_minutes=settings.access_token_expire_minutes)


@router.post(
    "/auth/login",
    response_model=TokenResponse,
    summary="Log in, get a bearer token",
    responses={401: {"description": "Invalid username or password"}},
)
@limiter.limit(settings.rate_limit_login)
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)):
    user = crud.get_user_by_username(db, payload.username)
    # Constant-time password check: always compute verify_password against either the user's
    # actual password hash or a precomputed dummy hash, preventing username enumeration via timing attacks.
    target_hash = user.password_hash if user else DUMMY_BCRYPT_HASH
    is_valid_password = verify_password(payload.password, target_hash)

    if not user or not user.is_active or not is_valid_password:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token = create_access_token(user)
    return TokenResponse(access_token=token, expires_in_minutes=settings.access_token_expire_minutes)


@router.get("/auth/me", response_model=MeOut, summary="Who am I, per my current token")
def me(claims: Claims = Depends(require_auth)):
    return MeOut(user_id=claims.user_id or 0, username=claims.username, tenant_id=claims.tenant_id, role=claims.role)


@router.get(
    "/public-key",
    summary="RSA public key (PEM) for verifying this service's JWTs locally",
    description=(
        "Any service that trusts this identity service can fetch this once "
        "(cache it) and verify tokens with it directly - RS256, no need to "
        "call back here per request. Rotate by regenerating the keypair, "
        "which invalidates all previously-issued tokens."
    ),
)
def public_key():
    return Response(content=get_public_key_pem(), media_type="application/x-pem-file")
