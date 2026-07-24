import uuid

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class EncryptedVault(Base):
    """An end-to-end-encrypted backup of a user's TOTP vault.

    The server stores ONLY ciphertext — it never sees the passphrase, the
    derived key, or the plaintext secrets. Decryption happens exclusively in the
    Flutter app. `nonce` and `kdf_salt` are not secret; they're required inputs
    to decrypt and are safe to store. A full server/DB breach leaks nothing
    usable. One vault per user (upserted on backup)."""

    __tablename__ = "encrypted_vaults"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,  # one vault per user
        index=True,
    )
    ciphertext: Mapped[str] = mapped_column(Text)  # base64(AES-GCM ciphertext)
    nonce: Mapped[str] = mapped_column(String)  # base64 GCM nonce
    kdf_salt: Mapped[str] = mapped_column(String)  # base64 PBKDF2 salt
    kdf_iterations: Mapped[int] = mapped_column(Integer)  # so params can evolve
    version: Mapped[int] = mapped_column(Integer, default=1)  # optimistic concurrency
