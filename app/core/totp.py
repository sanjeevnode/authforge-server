"""TOTP + recovery-code logic, isolated from HTTP/DB (plan convention).

TOTP secret: reversible (encrypted elsewhere) — server recomputes codes.
Recovery codes: one-way hashed here — only ever compared, never re-shown.
"""

import secrets

import pyotp

from app.core.security import hash_token  # sha256 hex — reuse for recovery codes

_ISSUER = "AuthForge"


def generate_secret() -> str:
    """Random base32 TOTP secret (what the authenticator app stores)."""
    return pyotp.random_base32()


def build_otpauth_uri(secret: str, email: str) -> str:
    """The otpauth:// URI a QR encodes. Issuer+label show in the authenticator app."""
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=_ISSUER)


def verify_code(secret: str, code: str) -> bool:
    """True if `code` is valid now. valid_window=1 tolerates ±one 30s step of
    clock drift between server and phone (standard practice)."""
    return pyotp.TOTP(secret).verify(code, valid_window=1)


# --- Recovery codes --------------------------------------------------------

def generate_recovery_codes(n: int = 10) -> list[str]:
    """n human-friendly codes like 'A1B2-C3D4'. Returned once to the user; we
    store only their hashes."""
    codes = []
    for _ in range(n):
        raw = secrets.token_hex(4).upper()          # 8 hex chars
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def hash_recovery_code(code: str) -> str:
    """One-way hash for storage/lookup. Normalize so 'a1b2-c3d4' == 'A1B2C3D4'."""
    normalized = code.replace("-", "").upper()
    return hash_token(normalized)


def demo() -> None:
    secret = generate_secret()

    # a freshly-computed code verifies; a wrong one doesn't
    good = pyotp.TOTP(secret).now()
    assert verify_code(secret, good)
    assert not verify_code(secret, "000000")

    uri = build_otpauth_uri(secret, "user@example.com")
    assert uri.startswith("otpauth://totp/") and "AuthForge" in uri

    # recovery codes: 10, formatted, hash is normalization-insensitive
    codes = generate_recovery_codes()
    assert len(codes) == 10 and all("-" in c for c in codes)
    c = codes[0]
    assert hash_recovery_code(c) == hash_recovery_code(c.lower())
    assert hash_recovery_code(c) != c

    print("totp.py demo OK")


if __name__ == "__main__":
    demo()
