import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("PLATFORM_ADMIN_PASSWORD", "platformtestpass")
os.environ.setdefault("PLATFORM_API_KEY", "test-platform-key")
os.environ.setdefault("PRIVATE_KEY_PATH", "keys/test_private.pem")
os.environ.setdefault("PUBLIC_KEY_PATH", "keys/test_public.pem")
os.environ.setdefault("RATE_LIMIT_LOGIN", "1000/minute")
os.environ.setdefault("RATE_LIMIT_REGISTER", "1000/minute")

import pytest
from passlib.context import CryptContext


@pytest.fixture(scope="session", autouse=True)
def _fast_password_hashing():
    from app import security
    original_context = security.pwd_context
    security.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=4)
    yield
    security.pwd_context = original_context
