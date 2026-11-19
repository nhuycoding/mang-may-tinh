"""Generate a Self-signed Lab Root CA and Server TLS certificate (TLS 1.2+).

Outputs in `server/certs/` (or --out-dir):
- ca.key          : Lab Root CA private key (keep secure)
- ca.crt          : Lab Root CA certificate (can be trusted in lab browsers)
- server.key      : Server TLS private key
- server.crt      : Server TLS certificate signed by Lab CA (with SANs)
- fingerprint.json: SHA-256 fingerprints of server.crt and ca.crt for Agent Certificate Pinning

Usage:
    python -m server.scripts.generate_certs
    python -m server.scripts.generate_certs --ip 192.168.1.50 --dns ogk.lan
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def generate_lab_certificates(
    out_dir: Path,
    extra_dns: list[str] | None = None,
    extra_ips: list[str] | None = None,
    ca_days: int = 3650,
    server_days: int = 825,
) -> dict[str, str]:
    """Generate Lab Root CA and Server TLS certificate with SANs and SHA-256 fingerprint."""
    out_dir.mkdir(parents=True, exist_ok=True)
    now = _utc_now()

    # 1. Generate Root CA key & self-signed certificate
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OGK Lab Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, "OGK Lab Root CA"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=ca_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # 2. Generate Server key & leaf certificate signed by Root CA
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OGK Lab Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    dns_names = ["localhost", "ogk-server.local"] + list(extra_dns or [])
    ip_addrs = ["127.0.0.1", "::1"] + list(extra_ips or [])

    san_entries: list[x509.GeneralName] = [x509.DNSName(name) for name in dict.fromkeys(dns_names)]
    for ip_str in dict.fromkeys(ip_addrs):
        san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=server_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # 3. Write PEM files
    (out_dir / "ca.key").write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (out_dir / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    (out_dir / "server.key").write_bytes(
        server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (out_dir / "server.crt").write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))

    # 4. Write SHA-256 certificate fingerprints for Agent certificate pinning
    server_fp = server_cert.fingerprint(hashes.SHA256()).hex()
    ca_fp = ca_cert.fingerprint(hashes.SHA256()).hex()
    meta = {
        "server_cert_sha256": server_fp,
        "ca_cert_sha256": ca_fp,
        "dns_sans": list(dict.fromkeys(dns_names)),
        "ip_sans": list(dict.fromkeys(ip_addrs)),
        "generated_at_utc": now.isoformat(),
    }
    (out_dir / "fingerprint.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate OGK Lab CA and Server TLS certificates.")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("server/certs"),
        help="Output directory for certificates (default: server/certs)",
    )
    parser.add_argument(
        "--dns",
        action="append",
        default=[],
        help="Additional DNS SAN entry (can be repeated, e.g. --dns ogk.lan)",
    )
    parser.add_argument(
        "--ip",
        action="append",
        default=[],
        help="Additional IP SAN entry (can be repeated, e.g. --ip 192.168.1.50)",
    )
    args = parser.parse_args()

    meta = generate_lab_certificates(
        out_dir=args.out_dir,
        extra_dns=args.dns,
        extra_ips=args.ip,
    )
    print(f"[OGK] Certificates generated in: {args.out_dir.resolve()}")
    print(f"[OGK] Server Cert SHA-256 (for Agent Pinning): {meta['server_cert_sha256']}")
    print(f"[OGK] CA Cert SHA-256                        : {meta['ca_cert_sha256']}")
    print(f"[OGK] SAN DNS: {meta['dns_sans']} | SAN IPs: {meta['ip_sans']}")


if __name__ == "__main__":
    main()
