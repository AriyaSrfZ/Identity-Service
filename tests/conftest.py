import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("PLATFORM_ADMIN_PASSWORD", "platformtestpass")
os.environ.setdefault("PLATFORM_API_KEY", "test-platform-key")
os.environ.setdefault("PRIVATE_KEY_PATH", "keys/test_private.pem")
os.environ.setdefault("PUBLIC_KEY_PATH", "keys/test_public.pem")
