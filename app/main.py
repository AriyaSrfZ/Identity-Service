"""
Run locally with: uvicorn app.main:app --reload
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.database import Base, engine, SessionLocal
from app.security import hash_password
from app import crud
from app.models import User
from app.routers import auth, tenants, users
from app.routers.auth import limiter


def _bootstrap_platform_admin():
    """Creates the platform super_admin from env vars, once, if missing."""
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.role == "super_admin").first()
        if not existing:
            crud.create_user(
                db,
                username=settings.platform_admin_username,
                password_hash=hash_password(settings.platform_admin_password),
                tenant_id=None,
                role="super_admin",
            )
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    _bootstrap_platform_admin()
    yield


app = FastAPI(title="Identity Service", version="0.1.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}


app.include_router(auth.router)
app.include_router(tenants.router)
app.include_router(users.router)
