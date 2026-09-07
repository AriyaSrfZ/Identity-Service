"""
RS256 JWT: signed with a private key only this service holds, verified
by anyone holding the public key - so consuming services (the QR
generator, link shortener, anything else) can verify a token locally,
with no network call back to this service per request. See GET /public-key.

The keypair is generated once, on first startup, and persisted to disk.
In Docker, mount the `keys/` directory as a volume - if the keypair is
regenerated (e.g. the volume is lost), every previously-issued token
becomes invalid and everyone has to log in again.
"""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt, JWTError
from passlib.context import CryptContext

from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def _ensure_keypair() -> None:
    priv_path = Path(settings.private_key_path)
    pub_path = Path(settings.public_key_path)
    if priv_path.exists() and pub_path.exists():
        return

    priv_path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    priv_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path.write_bytes(priv_bytes)
    pub_path.write_bytes(pub_bytes)
    os.chmod(priv_path, 0o600)


_ensure_keypair()
_PRIVATE_KEY = Path(settings.private_key_path).read_text()
_PUBLIC_KEY = Path(settings.public_key_path).read_text()


def get_public_key_pem() -> str:
    return _PUBLIC_KEY


def create_access_token(user) -> str:
    """user is an app.models.User instance."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "tenant_id": user.tenant_id,
        "role": user.role,
        "iss": settings.jwt_issuer,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(payload, _PRIVATE_KEY, algorithm="RS256")


def decode_token(token: str) -> Optional[dict]:
    """Returns the decoded claims, or None if the token is invalid/expired.
    This is exactly what a consuming service does too, using the public
    key from GET /public-key instead of holding the private key."""
    try:
        return jwt.decode(token, _PUBLIC_KEY, algorithms=["RS256"], issuer=settings.jwt_issuer)
    except JWTError:
        return None
