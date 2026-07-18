"""Reversible encryption for the TOTP secret (Fernet, symmetric).

Why reversible (vs hashing)? The server must recover the RAW secret to compute
the current TOTP code on every login. So we encrypt (can decrypt), not hash.
Recovery codes are the opposite — hashed one-way, like passwords.
"""

from cryptography.fernet import Fernet

from app.config import settings

_fernet = Fernet(settings.mfa_encryption_key.encode())


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a TOTP secret for storage. Returns a URL-safe token string."""
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a stored TOTP secret back to its raw base32 form."""
    return _fernet.decrypt(ciphertext.encode()).decode()
