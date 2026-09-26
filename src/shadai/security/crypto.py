"""Fernet encryption for stored secrets (API keys, passwords)."""

from __future__ import annotations

from cryptography.fernet import Fernet

_fernet: Fernet | None = None


def init_crypto(encryption_key: str) -> None:
    """Initialize the Fernet cipher with the provided key."""
    global _fernet
    _fernet = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a plaintext string, returning a base64-encoded ciphertext."""
    if _fernet is None:
        raise RuntimeError("Crypto not initialized. Call init_crypto first.")
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a base64-encoded ciphertext, returning the original plaintext."""
    if _fernet is None:
        raise RuntimeError("Crypto not initialized. Call init_crypto first.")
    return _fernet.decrypt(ciphertext.encode()).decode()
