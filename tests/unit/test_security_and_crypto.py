"""Unit tests for cryptographic primitives, Argon2id, URL/SLD sanitization, rate limiting, and Agent DPAPI fallback."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from agent.src.storage.dpapi import protect_secret, unprotect_secret
from server.app.crypto import (
    decrypt_field,
    encrypt_field,
    sign_policy_payload,
    verify_policy_signature,
)
from server.app.security import (
    InMemoryIPRateLimiter,
    hash_password,
    normalize_second_level_domain,
    sanitize_event_subject,
    verify_password,
)


def test_aes_gcm_encrypt_decrypt_roundtrip():
    ciphertext = encrypt_field("Be An — Sensitive Name")
    assert ciphertext != "Be An — Sensitive Name"
    assert decrypt_field(ciphertext) == "Be An — Sensitive Name"


def test_aes_gcm_tampered_ciphertext_rejected():
    ct = encrypt_field("secret-value")
    tampered = ct[:-4] + ("AAAA" if not ct.endswith("AAAA") else "BBBB")
    with pytest.raises((InvalidTag, ValueError)):
        decrypt_field(tampered)


def test_hmac_policy_signature_valid_and_tamper_rejected():
    payload = '{"policy_version":1,"weekday_quota_sec":3600}'
    sig = sign_policy_payload(payload, "device-secret-key")
    assert verify_policy_signature(payload, sig, "device-secret-key") is True
    assert verify_policy_signature(payload.replace("3600", "9999"), sig, "device-secret-key") is False
    assert verify_policy_signature(payload, sig, "wrong-secret") is False


def test_argon2id_password_hashing_and_min_length():
    with pytest.raises(ValueError):
        hash_password("short99")
    hashed = hash_password("StrongPass123!")
    assert hashed.startswith("$argon2id$")
    assert verify_password("StrongPass123!", hashed) is True
    assert verify_password("WrongPass123!", hashed) is False


def test_second_level_domain_strips_full_urls():
    assert normalize_second_level_domain("https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=42") == "youtube.com"
    assert normalize_second_level_domain("sub.deep.khanacademy.org/math/algebra") == "khanacademy.org"
    assert normalize_second_level_domain("portal.hcmus.edu.vn/login") == "hcmus.edu.vn"


def test_sanitize_event_subject_strips_paths_and_urls():
    assert sanitize_event_subject("domain_query", "https://m.facebook.com/messages/t/123") == "facebook.com"
    assert sanitize_event_subject("app_start", r"C:\Program Files\Google\Chrome\chrome.exe") == "chrome.exe"


def test_ip_rate_limiter_enforces_window_limit():
    limiter = InMemoryIPRateLimiter()
    for _ in range(3):
        assert limiter.check("10.0.0.5", "login", limit=3, window_sec=60) is True
    assert limiter.check("10.0.0.5", "login", limit=3, window_sec=60) is False
    assert limiter.check("10.0.0.6", "login", limit=3, window_sec=60) is True


def test_agent_dpapi_fallback_protect_unprotect():
    blob = protect_secret("agent-refresh-token-xyz")
    assert b"agent-refresh-token-xyz" not in blob
    assert unprotect_secret(blob) == "agent-refresh-token-xyz"
