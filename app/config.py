from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- App ---
    app_name: str = "authforge"
    environment: str = "development"
    debug: bool = True

    # --- Database ---
    database_url: str

    # --- Redis ---
    redis_url: str

    # --- JWT / security ---
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # --- MFA ---
    mfa_encryption_key: str  # Fernet key; encrypts the TOTP secret at rest

    # --- Logging ---
    log_level: str = "INFO"

    # --- CORS ---
    # Comma-separated allow-list of Web Portal origins. Never "*".
    cors_origins: str = (
        "http://localhost:5173,http://127.0.0.1:5173,https://app.authforge.sanjeevnode.in"
    )

    # --- Refresh-token cookie ---
    # httpOnly cookie holding the refresh token (JS can't read it -> XSS-safe).
    refresh_cookie_name: str = "authforge_refresh"
    # Shared parent domain so the cookie works across api. and app. subdomains.
    # Empty in local dev (host-only cookie on localhost).
    cookie_domain: str = ""
    # secure=True + samesite=none needed for cross-site (prod). Local dev: lax/insecure.
    cookie_secure: bool = False
    cookie_samesite: str = "lax"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    # Read from .env, ignore any extra vars in the file we haven't declared here
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


# One shared, validated instance the whole app imports.
settings = Settings()
