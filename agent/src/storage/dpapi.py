"""Data-at-rest secret protection for OGK-Agent (Windows DPAPI with AES-GCM fallback)."""

from __future__ import annotations

import base64
import hashlib
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_DPAPI_PREFIX = b"DPAPI:"
_AES_PREFIX = b"AESGCM:"


def _fallback_key() -> bytes:
    """Derive a 32-byte AES key from env var (used only when DPAPI is unavailable, e.g. CI/tests)."""
    env_key = os.environ.get("OGK_AGENT_FALLBACK_KEY", "")
    if env_key:
        try:
            raw = base64.urlsafe_b64decode(env_key.encode("ascii"))
            if len(raw) == 32:
                return raw
        except Exception:
            pass
    # Machine-local deterministic fallback for unit tests only
    seed = f"{os.environ.get('COMPUTERNAME', 'ogk-host')}:{os.environ.get('USERNAME', 'system')}:ogk"
    return hashlib.sha256(seed.encode("utf-8")).digest()


def protect_secret(plaintext: str) -> bytes:
    """Encrypt a secret string using Windows DPAPI (LocalMachine) or AES-256-GCM fallback."""
    data = plaintext.encode("utf-8")
    if sys.platform == "win32" and os.environ.get("OGK_DISABLE_DPAPI") != "1":
        try:
            import win32crypt  # type: ignore

            # CRYPTPROTECT_LOCAL_MACHINE = 0x4 so LocalSystem Service can decrypt across reboots
            blob = win32crypt.CryptProtectData(data, "OGK-Agent Secret", None, None, None, 0x4)
            return _DPAPI_PREFIX + blob
        except Exception:
            pass

    nonce = os.urandom(12)
    ct = AESGCM(_fallback_key()).encrypt(nonce, data, None)
    return _AES_PREFIX + nonce + ct


def unprotect_secret(blob: bytes) -> str:
    """Decrypt a secret previously protected by `protect_secret`."""
    if blob.startswith(_DPAPI_PREFIX):
        import win32crypt  # type: ignore

        _desc, plain = win32crypt.CryptUnprotectData(blob[len(_DPAPI_PREFIX) :], None, None, None, 0)
        return plain.decode("utf-8")

    if blob.startswith(_AES_PREFIX):
        raw = blob[len(_AES_PREFIX) :]
        nonce, ct = raw[:12], raw[12:]
        plain = AESGCM(_fallback_key()).decrypt(nonce, ct, None)
        return plain.decode("utf-8")

    raise ValueError("Unknown secret encryption prefix.")
