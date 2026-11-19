"""CLI enrollment helper for OGK-Agent on a Windows 10/11 machine.

Usage:
    python -m agent.scripts.enroll --server https://127.0.0.1:8443 --code ABCD1234 --pin <64-char-sha256>
"""

from __future__ import annotations

import argparse
import hashlib
import platform
import socket
import uuid

from agent.src.config import AgentConfig
from agent.src.service.net_client import AgentNetClient
from agent.src.storage.db import AgentLocalDB
from agent.src.storage.repository import AgentRepository


def compute_device_fingerprint() -> str:
    """Compute a deterministic hardware fingerprint for this Windows endpoint."""
    raw = f"{platform.node()}|{uuid.getnode()}|{platform.machine()}|{platform.processor()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Enroll this Windows machine into OGK-Server.")
    parser.add_argument("--server", required=True, help="OGK-Server base URL (e.g. https://127.0.0.1:8443)")
    parser.add_argument("--code", required=True, help="8-character pairing code from Parent Dashboard")
    parser.add_argument(
        "--pin",
        required=True,
        help="Pinned server TLS certificate SHA-256 fingerprint (from server/certs/fingerprint.json)",
    )
    parser.add_argument("--name", default=socket.gethostname(), help="Friendly device name")
    args = parser.parse_args()

    cfg = AgentConfig.from_env()
    client = AgentNetClient(server_url=args.server, pinned_cert_sha256=args.pin)
    fingerprint = compute_device_fingerprint()
    os_ver = f"{platform.system()} {platform.release()} ({platform.version()})"

    print(f"[OGK-Agent] Verifying TLS Certificate Pin & enrolling '{args.name}'...")
    result = client.enroll(
        pairing_code=args.code.strip().upper(),
        device_fingerprint=fingerprint,
        device_name=args.name,
        os_version=os_ver,
    )

    repo = AgentRepository(AgentLocalDB(cfg.db_path))
    repo.save_identity(
        device_id=result["device_id"],
        child_id=result["child_id"],
        server_url=args.server,
        server_cert_sha256=args.pin,
        access_token=result["access_token"],
        refresh_token=result["refresh_token"],
        hmac_secret=result["hmac_secret"],
    )
    print(f"[OGK-Agent] Enrollment succeeded! device_id={result['device_id']} child_id={result['child_id']}")
    print(f"[OGK-Agent] Credentials stored encrypted in {cfg.db_path}")


if __name__ == "__main__":
    main()
