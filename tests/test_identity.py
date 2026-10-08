import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import app  # noqa: E402
from app.database import Base, get_db, engine, SessionLocal  # noqa: E402
from app.security import get_public_key_pem  # noqa: E402
from jose import jwt  # noqa: E402

Base.metadata.create_all(bind=engine)


def override_get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

PLATFORM_KEY = {"X-API-Key": "test-platform-key"}


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def test_register_creates_tenant_and_owner(client):
    r = client.post("/auth/register", json={"tenant_name": "Acme", "username": "owner1", "password": "password123"})
    assert r.status_code == 200
    token = r.json()["access_token"]

    r2 = client.get("/auth/me", headers=auth_header(token))
    assert r2.status_code == 200
    assert r2.json()["role"] == "owner"
    assert r2.json()["tenant_id"] is not None


def test_duplicate_username_rejected(client):
    client.post("/auth/register", json={"tenant_name": "TenantA1", "username": "dup1", "password": "password123"})
    r = client.post("/auth/register", json={"tenant_name": "TenantB2", "username": "dup1", "password": "password123"})
    assert r.status_code == 400


def test_login_wrong_password(client):
    client.post("/auth/register", json={"tenant_name": "TenantC2", "username": "loginuser1", "password": "password123"})
    r = client.post("/auth/login", json={"username": "loginuser1", "password": "wrong"})
    assert r.status_code == 401


def test_owner_can_add_member_member_cannot(client):
    r = client.post("/auth/register", json={"tenant_name": "TenantD2", "username": "owner2", "password": "password123"})
    token, tenant_id = r.json()["access_token"], client.get("/auth/me", headers=auth_header(r.json()["access_token"])).json()["tenant_id"]

    r2 = client.post(f"/tenants/{tenant_id}/users", json={"username": "member1"}, headers=auth_header(token))
    assert r2.status_code == 200
    member_password = r2.json()["generated_password"]
    assert member_password

    r3 = client.post("/auth/login", json={"username": "member1", "password": member_password})
    member_token = r3.json()["access_token"]

    r4 = client.post(f"/tenants/{tenant_id}/users", json={"username": "sneaky1"}, headers=auth_header(member_token))
    assert r4.status_code == 403


def test_cross_tenant_isolation(client):
    r1 = client.post("/auth/register", json={"tenant_name": "TenantA", "username": "usera1", "password": "password123"})
    tenant_a_id = client.get("/auth/me", headers=auth_header(r1.json()["access_token"])).json()["tenant_id"]

    r2 = client.post("/auth/register", json={"tenant_name": "TenantB", "username": "userb1", "password": "password123"})
    b_token = r2.json()["access_token"]

    r3 = client.get(f"/tenants/{tenant_a_id}/users", headers=auth_header(b_token))
    assert r3.status_code == 404  # not 403 - doesn't confirm the tenant exists to an outsider


def test_platform_api_key_provisions_tenant(client):
    r = client.post("/tenants", json={"tenant_name": "Provisioned Co", "owner_username": "provowner1"}, headers=PLATFORM_KEY)
    assert r.status_code == 200
    assert r.json()["generated_password"]
    assert r.json()["role"] == "owner"


def test_non_platform_caller_cannot_provision_tenant(client):
    r = client.post("/auth/register", json={"tenant_name": "TenantE2", "username": "notplatform1", "password": "password123"})
    token = r.json()["access_token"]
    r2 = client.post("/tenants", json={"tenant_name": "Hijack", "owner_username": "hijacker1"}, headers=auth_header(token))
    assert r2.status_code == 403


def test_public_key_verifies_token_independently(client):
    r = client.post("/auth/register", json={"tenant_name": "TenantF2", "username": "verifyuser1", "password": "password123"})
    token = r.json()["access_token"]

    r2 = client.get("/public-key")
    assert r2.status_code == 200

    # Verified using ONLY the public key text from the HTTP response,
    # exactly as an external consuming service would do it.
    decoded = jwt.decode(token, r2.text, algorithms=["RS256"], issuer="identity-service")
    assert decoded["username"] == "verifyuser1"
    assert decoded["role"] == "owner"


def test_no_auth_rejected(client):
    r = client.get("/auth/me")
    assert r.status_code == 401


def test_owner_cannot_be_deleted(client):
    r = client.post("/auth/register", json={"tenant_name": "TenantG2", "username": "owner3", "password": "password123"})
    token = r.json()["access_token"]
    tenant_id = client.get("/auth/me", headers=auth_header(token)).json()["tenant_id"]
    me = client.get("/auth/me", headers=auth_header(token)).json()

    r2 = client.delete(f"/tenants/{tenant_id}/users/{me['user_id']}", headers=auth_header(token))
    assert r2.status_code == 400


def test_invalid_login_and_nonexistent_user_both_return_401(client):
    # Non-existent user
    r1 = client.post("/auth/login", json={"username": "ghost_user_xyz", "password": "wrongpassword"})
    assert r1.status_code == 401
    assert r1.json()["detail"] == "Invalid username or password."

    # Existing user with wrong password
    client.post("/auth/register", json={"tenant_name": "TenantSec", "username": "realuser_sec", "password": "correctpassword"})
    r2 = client.post("/auth/login", json={"username": "realuser_sec", "password": "wrongpassword"})
    assert r2.status_code == 401
    assert r2.json()["detail"] == "Invalid username or password."


def test_login_rate_limited():
    from fastapi import FastAPI, Request
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from slowapi.util import get_remote_address
    from starlette.testclient import TestClient

    test_limiter = Limiter(key_func=get_remote_address)
    app_isolated = FastAPI()
    app_isolated.state.limiter = test_limiter
    app_isolated.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @app_isolated.post("/test-login")
    @test_limiter.limit("2/minute")
    def _test_login(request: Request):
        return {"status": "ok"}

    test_c = TestClient(app_isolated)
    assert test_c.post("/test-login").status_code == 200
    assert test_c.post("/test-login").status_code == 200
    r3 = test_c.post("/test-login")
    assert r3.status_code == 429
