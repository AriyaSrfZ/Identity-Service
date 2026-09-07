"""
Central configuration, read from environment variables (via .env locally,
or real env vars in Docker/production).
"""

import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./data/identity.db")

    # Platform-level bootstrap super-admin (manages tenants, not tied to any one tenant)
    platform_admin_username: str = os.getenv("PLATFORM_ADMIN_USERNAME", "platform_admin")
    platform_admin_password: str = os.getenv("PLATFORM_ADMIN_PASSWORD", "change_this_password")

    # Trusted server-to-server key: lets another service (or an ops script)
    # provision tenants/users without a human logging in first.
    platform_api_key: str = os.getenv("PLATFORM_API_KEY", "")

    # RSA keypair for signing/verifying JWTs (RS256). Generated on first
    # startup if missing - see app/security.py. Mount `keys/` as a volume
    # in Docker so the same keypair persists across container restarts;
    # if the key changes, every previously-issued token becomes invalid.
    private_key_path: str = os.getenv("PRIVATE_KEY_PATH", "keys/private_key.pem")
    public_key_path: str = os.getenv("PUBLIC_KEY_PATH", "keys/public_key.pem")

    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    jwt_issuer: str = os.getenv("JWT_ISSUER", "identity-service")


settings = Settings()
