"""Cryptographic primitives for OGK-Server.

Provides:
- AES-256-GCM encryption/decryption for sensitive fields at rest (F5).
- HMAC-SHA256 policy payload signing and verification (Section 2A).
- SHA-256 token/secret hashing for database storage and revocation lists (F5).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from server.app.config import get_settings


def encrypt_field(plaintext: str, key: bytes | None = None) -> str:
    """Encrypt a UTF-8 string using AES-256-GCM. Returns base64url(nonce || ciphertext)."""
    aes_key = key if key is not None else get_settings().get_master_key_bytes()
    nonce = os.urandom(12)  # 96-bit standard GCM nonce
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_field(token: str, key: bytes | None = None) -> str:
    """Decrypt a base64url(nonce || ciphertext) string encrypted with AES-256-GCM."""
    aes_key = key if key is not None else get_settings().get_master_key_bytes()
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    if len(raw) < 12 + 16:
        raise ValueError("Invalid encrypted payload length.")
    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext.decode("utf-8")


def hash_token(raw_token: str) -> str:
    """Return hex SHA-256 digest of a token, pairing code, or fingerprint."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def canonical_json(payload: dict[str, Any]) -> str:
    """Serialize a dictionary deterministically for HMAC signing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign_policy_payload(payload_json: str, secret: str) -> str:
    """Compute HMAC-SHA256 hex digest over canonical policy JSON."""
    return hmac.new(
        secret.encode("utf-8"),
        payload_json.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_policy_signature(payload_json: str, signature_hex: str, secret: str) -> bool:
    """Constant-time verification of HMAC-SHA256 policy signature."""
    expected = sign_policy_payload(payload_json, secret)
    return hmac.compare_digest(expected, signature_hex)
