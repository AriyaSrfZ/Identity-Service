# Identity Service

Standalone, reusable multi-tenant user management + authentication.
Any app (this project's siblings, or anything else) can use this as its
account system instead of building its own — see "Using this from
another service" below.

## Architecture
- **Tenant**: one customer organization. Everything a consuming app
  builds (links, QR codes, whatever) should be tagged with a `tenant_id`,
  not a `user_id` — so a whole company's data stays grouped as individual
  users come and go.
- **User**: belongs to exactly one tenant, with a role scoped to it:
  `owner` > `admin` > `member`. A platform-level `super_admin` (bootstrapped
  from `.env`) manages tenants themselves, not any one tenant's data.
- **JWT (RS256)**: login/register return a signed token. Any service
  that fetches `GET /public-key` once can verify tokens **locally** —
  no network round-trip to this service per request. This is the
  standard pattern for multi-tenant auth across microservices (tenant-scoped
  claims + portable local verification), not something specific to this repo.
- **Shared database, tenant_id column** for isolation (not a separate
  database per tenant) — the right tradeoff at this scale; simpler to
  operate, and still fully isolated since every query is scoped by
  `tenant_id` server-side, never trusted from client input alone.

## Quick start (Docker, recommended)
```bash
cp .env.example .env
# edit .env: set PLATFORM_ADMIN_PASSWORD and PLATFORM_API_KEY
docker compose up --build
```
Service runs at `http://localhost:8001`.

## Quick start (local, no Docker)
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env   # edit it
uvicorn app.main:app --reload
```
Runs at `http://127.0.0.1:8000`. Interactive docs at `/docs`.

Run tests: `pytest -v`

## Core endpoints
| Endpoint | Who can call it | What it does |
|---|---|---|
| `POST /auth/register` | anyone | Creates a new tenant + its first user (role=`owner`) |
| `POST /auth/login` | anyone | Returns a bearer token |
| `GET /auth/me` | any valid token | Who am I, per my token |
| `GET /public-key` | anyone | RSA public key (PEM) for verifying tokens locally |
| `POST /tenants` | platform admin/API key | Provision a tenant + owner in one call (for another app to call automatically) |
| `GET /tenants` | platform admin/API key | List all tenants |
| `POST /tenants/{id}/users` | that tenant's owner/admin, or platform | Add a member to a tenant |
| `GET /tenants/{id}/users` | that tenant's members, or platform | List a tenant's members |
| `DELETE /tenants/{id}/users/{user_id}` | that tenant's owner/admin, or platform | Remove a member (not the owner) |

Full request/response shapes: `/docs` (Swagger) once running.

## Using this from another service
1. On startup, fetch `GET /public-key` once and cache the PEM text.
2. When a request arrives with `Authorization: Bearer <token>`, verify
   it locally:
   ```python
   from jose import jwt
   claims = jwt.decode(token, cached_public_key, algorithms=["RS256"], issuer="identity-service")
   # claims = {"sub": user_id, "username": ..., "tenant_id": ..., "role": ...}
   ```
3. Use `claims["tenant_id"]` to scope every database query in your own
   service — that's the actual isolation boundary, not just checking
   the token is valid. A valid token from tenant A must never let you
   read tenant B's rows.
4. For server-to-server calls (no human user involved), use the
   `PLATFORM_API_KEY` against `/tenants` and `/tenants/{id}/users`
   instead of a bearer token.

The QR generator service in this same delivery is built exactly this
way — see its README for the concrete integration.

## Security notes
- Rotating the RSA keypair (deleting the `keys/` volume) invalidates
  every previously-issued token — everyone has to log in again. This is
  intentional and matches how key rotation works in any RS256 setup.
- `PLATFORM_API_KEY` is effectively a master key across every tenant.
  Treat it like a root password, not a per-app credential.
- Passwords are hashed with bcrypt (`bcrypt==4.0.1` pinned — newer
  versions have a known incompatibility with `passlib` 1.7.4 that
  breaks hashing entirely; don't upgrade this without checking that's fixed upstream).
