"""Secure HTTP & WebSocket client for OGK-Agent with TLS 1.2+ Certificate Pinning and Policy HMAC Verification."""

from __future__ import annotations

import hashlib
import hmac
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

import httpx


class CertificatePinningError(RuntimeError):
    """Raised when the server's TLS certificate SHA-256 fingerprint does not match the pinned fingerprint."""


class PolicyTamperError(RuntimeError):
    """Raised when a fetched policy fails HMAC-SHA256 integrity verification."""


def compute_der_sha256(der_bytes: bytes) -> str:
    """Return lowercase hex SHA-256 fingerprint of a DER-encoded X.509 certificate."""
    return hashlib.sha256(der_bytes).hexdigest().lower()


def verify_server_cert_pin(server_url: str, expected_sha256: str, timeout: float = 5.0) -> str:
    """Connect over TLS 1.2+ to `server_url` and verify peer certificate SHA-256 fingerprint.

    Refuses connection by raising `CertificatePinningError` on any mismatch (F5).
    """
    parsed = urlparse(server_url)
    if parsed.scheme != "https":
        raise CertificatePinningError("Refusing non-HTTPS server URL when certificate pinning is enabled.")

    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 443
    expected = expected_sha256.strip().lower().replace(":", "")
    if len(expected) != 64:
        raise CertificatePinningError("Invalid pinned SHA-256 fingerprint format (expected 64 hex chars).")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Self-signed lab certs are authenticated directly via SHA-256 leaf fingerprint pinning
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)
            if not der_cert:
                raise CertificatePinningError("Server presented no TLS certificate.")
            actual_fp = compute_der_sha256(der_cert)

    if not hmac.compare_digest(actual_fp, expected):
        raise CertificatePinningError(
            f"TLS Certificate Pinning FAILED! Expected {expected}, got {actual_fp}. Connection refused."
        )
    return actual_fp


def verify_policy_hmac(payload_json: str, signature_hmac: str, hmac_secret: str) -> bool:
    """Verify HMAC-SHA256 signature on canonical policy payload before applying (Section 2A)."""
    expected = hmac.new(
        hmac_secret.encode("utf-8"),
        payload_json.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature_hmac.strip().lower())


class AgentNetClient:
    """HTTP client enforcing TLS 1.2+ certificate pinning and automatic token refresh."""

    def __init__(
        self,
        server_url: str,
        pinned_cert_sha256: str = "",
        ca_cert_path: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.pinned_cert_sha256 = pinned_cert_sha256.strip().lower()
        self.ca_cert_path = ca_cert_path
        self.timeout = timeout
        self._pin_verified = False

    def _ensure_pin_verified(self) -> None:
        if self.pinned_cert_sha256 and self.server_url.startswith("https://"):
            verify_server_cert_pin(self.server_url, self.pinned_cert_sha256, timeout=self.timeout)
            self._pin_verified = True

    def _build_client(self) -> httpx.Client:
        self._ensure_pin_verified()
        verify: bool | str = self.ca_cert_path if self.ca_cert_path else (not bool(self.pinned_cert_sha256))
        return httpx.Client(base_url=self.server_url, verify=verify, timeout=self.timeout)

    def enroll(
        self,
        *,
        pairing_code: str,
        device_fingerprint: str,
        device_name: str,
        os_version: str,
        agent_version: str = "1.0.0",
    ) -> dict[str, Any]:
        with self._build_client() as client:
            resp = client.post(
                "/enroll",
                json={
                    "pairing_code": pairing_code,
                    "device_fingerprint": device_fingerprint,
                    "device_name": device_name,
                    "os_version": os_version,
                    "agent_version": agent_version,
                },
            )
            resp.raise_for_status()
            return resp.json()

    def refresh_access_token(self, refresh_token: str) -> dict[str, Any]:
        with self._build_client() as client:
            resp = client.post("/enroll/refresh", json={"refresh_token": refresh_token})
            resp.raise_for_status()
            return resp.json()

    def fetch_verified_policy(self, access_token: str, hmac_secret: str) -> dict[str, Any]:
        """Fetch GET /policy and strictly verify HMAC-SHA256 signature. Rejects tampered policies."""
        with self._build_client() as client:
            resp = client.get("/policy", headers={"Authorization": f"Bearer {access_token}"})
            resp.raise_for_status()
            data = resp.json()

        if not verify_policy_hmac(data["payload_json"], data["signature_hmac"], hmac_secret):
            raise PolicyTamperError("Fetched policy failed HMAC-SHA256 verification! Policy rejected.")
        return data

    def send_heartbeat(
        self,
        access_token: str,
        *,
        status: str,
        used_quota_sec_today: int,
        current_policy_version: int,
        client_time_iso: str,
        clock_tamper_detected: bool,
        remaining_sec_today: int | None = None
    ) -> dict[str, Any]:
        with self._build_client() as client:
            resp = client.post(
                "/events/heartbeat",
                headers={"Authorization": f"Bearer {access_token}"},
                json={
                    "status": status,
                    "used_quota_sec_today": used_quota_sec_today,
                    "remaining_sec_today": remaining_sec_today,
                    "current_policy_version": current_policy_version,
                    "client_time": client_time_iso,
                    "clock_tamper_detected": clock_tamper_detected,
                },
            )
            resp.raise_for_status()
            return resp.json()

    def sync_event_batch(self, access_token: str, events: list[dict[str, Any]]) -> dict[str, Any]:
        payload_events = [
            {
                "idempotency_key": e["idempotency_key"],
                "ts": e["ts"],
                "type": e["type"],
                "subject": e["subject"],
                "duration_sec": int(e["duration_sec"]),
                "policy_id": e.get("policy_id"),
            }
            for e in events
        ]
        with self._build_client() as client:
            resp = client.post(
                "/events/batch",
                headers={"Authorization": f"Bearer {access_token}"},
                json={"events": payload_events},
            )
            resp.raise_for_status()
            return resp.json()

    def ack_command(self, access_token: str, command_id: str, status: str = "acknowledged") -> dict[str, Any]:
        with self._build_client() as client:
            resp = client.post(
                f"/commands/{command_id}/ack",
                headers={"Authorization": f"Bearer {access_token}"},
                json={"status": status},
            )
            resp.raise_for_status()
            return resp.json()

    def submit_extension_request(
        self, access_token: str, requested_minutes: int = 15, reason: str = ""
    ) -> dict[str, Any]:
        with self._build_client() as client:
            resp = client.post(
                "/events/extension-request",
                headers={"Authorization": f"Bearer {access_token}"},
                json={"requested_minutes": requested_minutes, "reason": reason},
            )
            resp.raise_for_status()
            return resp.json()

    def fetch_audit_logs(self, access_token: str) -> list[dict[str, Any]]:
        with self._build_client() as client:
            resp = client.get(
                "/audit/agent?page=1&page_size=30",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            return resp.json().get("items", [])
