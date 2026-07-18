# AuthForge — Identity Server

FastAPI backend for AuthForge: registration, login, JWT tokens, and TOTP-based
multi-factor auth. Owns all data; the only component with database access.

**Live:** https://server.authforge.sanjeevnode.in ·
**Docs:** https://server.authforge.sanjeevnode.in/docs

---

## Stack

| Concern | Choice |
|---|---|
| Framework | FastAPI |
| ORM / migrations | SQLAlchemy 2.0 + Alembic |
| Database | PostgreSQL 16 |
| Cache / rate-limit store | Redis 7 |
| Password hashing | Argon2id (`argon2-cffi`) |
| Access token | JWT, HS256, 15 min |
| Refresh token | opaque random, 7 days, rotating, stored as SHA-256 |
| MFA | TOTP (`pyotp`), secret Fernet-encrypted at rest |
| Packaging | uv |
| Runtime | Docker Compose |

---

## Quick start (local)

```bash
cp .env.example .env          # fill local values
docker compose up -d --build
docker compose exec app uv run alembic upgrade head
curl localhost:8000/health    # {"status":"healthy"}
```

Docs at http://localhost:8000/docs. Full guide: [docs/local-development.md](docs/local-development.md).

---

## API

All endpoints under `/api/v1`. Errors always return
`{"detail": "message", "code": "MACHINE_CODE"}` — clients switch on `code`.

### Auth (`/api/v1/auth`)

| Method | Path | Description |
|---|---|---|
| POST | `/register` | Create an account |
| POST | `/login` | Password login → token pair, or `{mfa_required, mfa_token}` if MFA on |
| POST | `/login/mfa` | Complete MFA login with OTP or a recovery code |
| POST | `/refresh` | Rotate refresh token → new pair (old one revoked) |
| POST | `/logout` | Revoke a refresh token |
| GET | `/me` | Current user (requires access token) |

### MFA (`/api/v1/mfa`, all require access token)

| Method | Path | Description |
|---|---|---|
| POST | `/setup` | Generate + store encrypted TOTP secret (not yet enabled) |
| GET | `/qr` | PNG QR code of the otpauth URI |
| POST | `/verify` | Verify first OTP → enable MFA, return 10 recovery codes once |
| POST | `/disable` | Disable MFA (requires password **and** current OTP) |
| GET | `/recovery` | Count of remaining recovery codes |

---

## Project structure

Layered ("clean") — dependencies point inward: `routers → repositories`,
`routers → core`; `core` depends on nothing app-specific.

```
app/
├── main.py            # app + router wiring + OpenAPI metadata
├── config.py          # pydantic-settings, reads .env
├── database.py        # engine, get_db, Base (shared id/created_at/updated_at)
├── core/              # pure logic — no HTTP, no cross-layer imports
│   ├── security.py    # argon2 hashing, JWT access/mfa tokens, refresh hashing
│   ├── crypto.py      # Fernet encrypt/decrypt for the TOTP secret
│   ├── totp.py        # pyotp wrapper + recovery-code helpers
│   ├── time.py        # store UTC, display IST (to_ist)
│   ├── deps.py        # get_current_user (Bearer auth guard)
│   ├── rate_limit.py  # Redis fixed-window limiter
│   ├── redis_client.py
│   └── logging.py
├── models/            # SQLAlchemy tables: user, refresh_token, recovery_code
├── schemas/           # Pydantic request/response contracts: auth, user, mfa
├── repositories/      # data access (SQL only): user, recovery_code
└── routers/           # HTTP endpoints: auth, mfa
alembic/               # migrations
docker-compose.yml       # local dev (hot reload, pgAdmin)
docker-compose.prod.yml  # production (internal-only PG/Redis, app on localhost)
nginx/                   # host nginx site config for prod
```

---

## Conventions

- **Timestamps:** stored UTC (`TIMESTAMPTZ`), returned in IST (`+05:30`) via `to_ist`.
- **IDs:** UUID v4 everywhere (no sequential integers — avoids enumeration).
- **Secrets in DB:** refresh tokens & recovery codes hashed (one-way);
  TOTP secret encrypted (reversible, needed to compute codes).
- **Rate limiting:** 5 attempts / 15 min per IP+email on `/login` (Redis).

---

## Documentation

- [docs/local-development.md](docs/local-development.md) — run + develop locally
- [docs/deployment.md](docs/deployment.md) — production architecture & operations
