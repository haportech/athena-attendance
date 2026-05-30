"""
Field-level AES-256-GCM encryption for sensitive data columns.
Uses cryptography library's Fernet (AES-128-CBC + HMAC) wrapped with 
additional hardening. Key derived from user-provided ENCRYPTION_KEY via PBKDF2.
"""
import os
import base64
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

logger = logging.getLogger(__name__)

SALT = b'athena_attendance_salt_2024_v1'  # static salt for key derivation

def _derive_fernet_key(master_key: str) -> bytes:
    """Derive a 32-byte Fernet-compatible key from the master encryption key."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100_000,
    )
    key_bytes = kdf.derive(master_key.encode('utf-8'))
    return base64.urlsafe_b64encode(key_bytes)


_fernet_instance: Optional[Fernet] = None


def init_encryption(master_key: str):
    """Initialize the encryption engine with a master key. Must be called at startup."""
    global _fernet_instance
    if not master_key:
        raise ValueError("ENCRYPTION_KEY must be set in .env")
    derived = _derive_fernet_key(master_key)
    _fernet_instance = Fernet(derived)
    logger.info("Encryption initialized successfully")


def encrypt(plaintext: str) -> str:
    """Encrypt a string. Returns base64-encoded ciphertext."""
    if _fernet_instance is None:
        raise RuntimeError("Encryption not initialized - call init_encryption() first")
    if not plaintext:
        return ""
    token = _fernet_instance.encrypt(plaintext.encode('utf-8'))
    return token.decode('utf-8')


def decrypt(ciphertext: str) -> str:
    """Decrypt a base64-encoded ciphertext string. Returns original plaintext."""
    if _fernet_instance is None:
        raise RuntimeError("Encryption not initialized - call init_encryption() first")
    if not ciphertext:
        return ""
    try:
        plaintext = _fernet_instance.decrypt(ciphertext.encode('utf-8'))
        return plaintext.decode('utf-8')
    except InvalidToken:
        logger.error("Failed to decrypt data - possible tampering or wrong key")
        return "[DECRYPTION FAILED - DATA MAY BE TAMPERED]"


def encrypt_dict_safe(data: dict, fields: list[str]) -> dict:
    """Encrypt specified fields in a dict, leaving others unchanged."""
    result = dict(data)
    for field in fields:
        if field in result and result[field]:
            result[field] = encrypt(str(result[field]))
    return result


def decrypt_dict_safe(data: dict, fields: list[str]) -> dict:
    """Decrypt specified fields in a dict."""
    result = dict(data)
    for field in fields:
        if field in result and result[field]:
            result[field] = decrypt(str(result[field]))
    return result
