from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.core.logging import setup_logging
from app.routers import auth, devices, mfa, sessions

setup_logging()

app = FastAPI(
    title="AuthForge Identity Server",
    version="0.1.0",
    description=(
        "Identity server for AuthForge — registration, login, JWT access tokens, "
        "and rotating refresh tokens.\n\n"
        "**Auth model:** short-lived access token (15 min, JWT) + long-lived rotating "
        "refresh token (7 days, opaque). Send the access token as "
        "`Authorization: Bearer <token>` on protected routes.\n\n"
        "**Errors** always look like `{\"detail\": \"...\", \"code\": \"MACHINE_CODE\"}` — "
        "switch on `code`, not the message.\n\n"
        "**Timestamps** are stored in UTC and returned in IST (`+05:30`)."
    ),
    openapi_tags=[
        {"name": "auth", "description": "Registration, login, token refresh/rotation, logout, and current-user."},
        {"name": "mfa", "description": "TOTP-based multi-factor auth: setup, QR, verify, disable, recovery codes."},
        {"name": "sessions", "description": "List and revoke active login sessions (device, IP, last active)."},
        {"name": "devices", "description": "Trusted devices that skip MFA; revoke to force MFA again."},
        {"name": "health", "description": "Liveness check."},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,  # explicit allow-list, never "*"
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(mfa.router)
app.include_router(sessions.router)
app.include_router(devices.router)


@app.get("/health", tags=["health"], summary="Liveness check")
async def health_check():
    return {"status": "healthy"}
