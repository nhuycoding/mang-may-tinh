"""F2: Local DNS Proxy (`127.0.0.1:53`) with Subdomain Blocking & SafeSearch Enforcement."""

from __future__ import annotations

import logging
import socket
import threading
from typing import Any, Callable

from dnslib import CNAME, QTYPE, RCODE, RR, A, DNSRecord
from dnslib.server import BaseResolver, DNSServer

logger = logging.getLogger("ogk.dns_proxy")

# Official SafeSearch VIP/CNAME targets (F2)
SAFESEARCH_CNAME_MAP: dict[str, str] = {
    "google.com": "forcesafesearch.google.com.",
    "www.google.com": "forcesafesearch.google.com.",
    "google.com.vn": "forcesafesearch.google.com.",
    "www.google.com.vn": "forcesafesearch.google.com.",
    "bing.com": "strict.bing.com.",
    "www.bing.com": "strict.bing.com.",
    "duckduckgo.com": "safe.duckduckgo.com.",
    "www.duckduckgo.com": "safe.duckduckgo.com.",
}


def extract_sld(qname: str) -> str:
    """Extract second-level domain ONLY for privacy-preserving logging (F3)."""
    host = qname.strip().lower().rstrip(".")
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host
    multi_tlds = {"co.uk", "org.uk", "com.vn", "edu.vn", "gov.vn", "net.vn", "com.au", "co.jp"}
    last_two = ".".join(parts[-2:])
    if len(parts) >= 3 and last_two in multi_tlds:
        return ".".join(parts[-3:])
    return last_two


def domain_matches_set(qname: str, domain_set: set[str]) -> str | None:
    """Return matching rule domain if `qname` equals or is a subdomain of any domain in `domain_set`."""
    host = qname.strip().lower().rstrip(".")
    if not host or not domain_set:
        return None
    parts = host.split(".")
    for i in range(len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in domain_set:
            return candidate
    return None


class OGKDNSResolver(BaseResolver):
    """Policy-aware DNS resolver enforcing exact+subdomain blocking and SafeSearch."""

    def __init__(
        self,
        *,
        upstream_host: str = "1.1.1.1",
        upstream_port: int = 53,
        block_mode: str = "nxdomain",  # "nxdomain" or "zero_ip"
        on_event: Callable[[str, str, str], None] | None = None,
    ) -> None:
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.block_mode = block_mode
        self.on_event = on_event  # callback(event_type, sld_subject, reason)

        self._lock = threading.RLock()
        self._safesearch_enabled = True
        self._allowed_domains: set[str] = set()
        self._blocked_domains: set[str] = set()

    def update_policy(self, policy_payload: dict[str, Any]) -> None:
        """Hot-reload DNS rules from a verified policy payload."""
        with self._lock:
            self._safesearch_enabled = bool(policy_payload.get("safesearch_enabled", True))
            self._allowed_domains = {
                d.strip().lower().rstrip(".")
                for d in policy_payload.get("allowed_domains", [])
                if d.strip()
            }
            blocked = set()
            for key in ("blocked_domains", "category_blocked_domains"):
                for d in policy_payload.get(key, []):
                    if d.strip():
                        blocked.add(d.strip().lower().rstrip("."))
            self._blocked_domains = blocked

    def _emit_event(self, event_type: str, sld: str, reason: str = "") -> None:
        if self.on_event is not None:
            try:
                self.on_event(event_type, sld, reason)
            except Exception:
                pass

    def _forward_upstream(self, request: DNSRecord) -> DNSRecord:
        """Forward allowed DNS query to upstream resolver via UDP."""
        raw = request.pack()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3.0)
            sock.sendto(raw, (self.upstream_host, self.upstream_port))
            data, _ = sock.recvfrom(4096)
        return DNSRecord.parse(data)

    def resolve(self, request: DNSRecord, handler=None) -> DNSRecord:
        qname = str(request.q.qname).strip().lower().rstrip(".")
        qtype = request.q.qtype
        sld = extract_sld(qname)

        with self._lock:
            safesearch = self._safesearch_enabled
            allowed = self._allowed_domains
            blocked = self._blocked_domains

        # 1. Explicit allowlist overrides blocklists
        is_explicitly_allowed = domain_matches_set(qname, allowed) is not None

        # 2. Block exact domain and all subdomains (F2)
        if not is_explicitly_allowed:
            matched_block = domain_matches_set(qname, blocked)
            if matched_block is not None:
                reply = request.reply()
                if self.block_mode == "zero_ip" and qtype == QTYPE.A:
                    reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
                else:
                    reply.header.rcode = RCODE.NXDOMAIN
                self._emit_event(
                    "blocked_domain",
                    sld,
                    f"Website '{sld}' is blocked by family safety policy (matched rule: {matched_block}).",
                )
                return reply

        # 3. SafeSearch Enforcement (F2)
        if safesearch and qname in SAFESEARCH_CNAME_MAP:
            target = SAFESEARCH_CNAME_MAP[qname]
            reply = request.reply()
            reply.add_answer(RR(request.q.qname, QTYPE.CNAME, rdata=CNAME(target), ttl=300))
            self._emit_event("domain_query", sld, f"SafeSearch enforced -> {target}")
            return reply

        # 4. Allowed query -> log SLD only and forward upstream
        self._emit_event("domain_query", sld, "")
        try:
            return self._forward_upstream(request)
        except Exception as exc:
            logger.debug("Upstream DNS forward failed for %s: %s", qname, exc)
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply


class LocalDNSProxyServer:
    """Wrapper managing the background UDP DNSServer thread on `127.0.0.1:53`."""

    def __init__(
        self,
        *,
        bind_host: str = "127.0.0.1",
        bind_port: int = 53,
        upstream_host: str = "1.1.1.1",
        upstream_port: int = 53,
        on_event: Callable[[str, str, str], None] | None = None,
    ) -> None:
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.resolver = OGKDNSResolver(
            upstream_host=upstream_host,
            upstream_port=upstream_port,
            on_event=on_event,
        )
        self._server: DNSServer | None = None

    def update_policy(self, policy_payload: dict[str, Any]) -> None:
        self.resolver.update_policy(policy_payload)

    def start(self) -> None:
        self._server = DNSServer(
            self.resolver,
            port=self.bind_port,
            address=self.bind_host,
            tcp=False,
        )
        self._server.start_thread()
        logger.info("Local DNS Proxy started on %s:%d", self.bind_host, self.bind_port)

    def stop(self) -> None:
        if self._server is not None:
            self._server.stop()
            self._server = None
