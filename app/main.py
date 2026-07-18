from fastapi import FastAPI

from app.config import settings
from app.core.logging import setup_logging
from app.routers import auth, mfa

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
        {"name": "health", "description": "Liveness check."},
    ],
)

app.include_router(auth.router)
app.include_router(mfa.router)


@app.get("/health", tags=["health"], summary="Liveness check")
async def health_check():
    return {"status": "healthy"}
