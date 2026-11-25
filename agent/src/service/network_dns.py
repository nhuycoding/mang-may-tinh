"""Windows Network DNS Binding Helper for KidGate Local DNS Proxy (127.0.0.1:53).

Automatically configures active Windows network adapters to point primary DNS to `127.0.0.1`
when the Agent starts with Administrator/SYSTEM privileges, flushes the Windows DNS cache,
and cleanly restores original DNS settings on Agent stop/uninstall.
"""

from __future__ import annotations

import ctypes
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger("ogk.network_dns")


def is_windows_admin() -> bool:
    """Return True if the current process is running with Administrator/SYSTEM privileges."""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_ps(script: str, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def flush_windows_dns_cache() -> None:
    """Run `ipconfig /flushdns` on Windows."""
    if sys.platform != "win32":
        return
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, timeout=10.0)
    except Exception as exc:
        logger.debug("ipconfig /flushdns failed: %s", exc)


def configure_system_dns(backup_file: Path, dns_ip: str = "127.0.0.1") -> list[dict[str, Any]]:
    """Point all active Windows network adapters to `dns_ip` and save original settings for restore."""
    if sys.platform != "win32":
        return []
    if not is_windows_admin():
        logger.warning("Skipping Windows DNS adapter configuration (not running as Administrator).")
        return []

    ps_query = (
        "$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false }; "
        "if (-not $adapters) { $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } }; "
        "$out = @(); "
        "foreach ($a in $adapters) { "
        "  $cur = (Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses; "
        "  $out += [PSCustomObject]@{ ifIndex = $a.ifIndex; Name = $a.Name; OriginalDNS = @($cur) } "
        "}; "
        "$out | ConvertTo-Json -Compress"
    )
    try:
        res = _run_ps(ps_query)
        raw = (res.stdout or "").strip()
        if not raw:
            return []
        parsed = json.loads(raw)
        adapters: list[dict[str, Any]] = parsed if isinstance(parsed, list) else [parsed]
    except Exception as exc:
        logger.warning("Failed to enumerate Windows network adapters: %s", exc)
        return []

    # Save backup only if not already backed up (prevents overwriting original DNS with 127.0.0.1 on restart)
    try:
        backup_file.parent.mkdir(parents=True, exist_ok=True)
        if not backup_file.exists():
            backup_file.write_text(json.dumps(adapters, indent=2), encoding="utf-8")
    except Exception as exc:
        logger.warning("Could not save DNS backup to %s: %s", backup_file, exc)

    configured: list[dict[str, Any]] = []
    for ad in adapters:
        idx = ad.get("ifIndex")
        name = ad.get("Name", "")
        if idx is None:
            continue
        ps_set = f"Set-DnsClientServerAddress -InterfaceIndex {int(idx)} -ServerAddresses ('{dns_ip}')"
        r = _run_ps(ps_set)
        if r.returncode == 0:
            configured.append(ad)
            logger.info("Configured DNS=%s on adapter '%s' (ifIndex=%s)", dns_ip, name, idx)
        else:
            # Fallback to netsh
            try:
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "dnsservers", f"name={name}", "source=static", f"address={dns_ip}", "validate=no"],
                    capture_output=True,
                    text=True,
                    timeout=10.0,
                )
                configured.append(ad)
            except Exception as exc:
                logger.warning("Failed to set DNS on adapter '%s': %s", name, exc)

    flush_windows_dns_cache()
    return configured


def restore_system_dns(backup_file: Path) -> None:
    """Restore Windows network adapters' original DNS settings (or reset to DHCP) and flush cache."""
    if sys.platform != "win32" or not is_windows_admin():
        return

    adapters: list[dict[str, Any]] = []
    if backup_file.exists():
        try:
            adapters = json.loads(backup_file.read_text(encoding="utf-8"))
        except Exception:
            adapters = []

    if adapters:
        for ad in adapters:
            idx = ad.get("ifIndex")
            orig = [s for s in (ad.get("OriginalDNS") or []) if s and s != "127.0.0.1"]
            if idx is None:
                continue
            if orig:
                addr_list = ",".join(f"'{s}'" for s in orig)
                _run_ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(idx)} -ServerAddresses ({addr_list})")
            else:
                _run_ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(idx)} -ResetServerAddresses")
        try:
            backup_file.unlink(missing_ok=True)
        except Exception:
            pass
    else:
        _run_ps(
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
            "ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }"
        )

    flush_windows_dns_cache()
    logger.info("Restored Windows system DNS settings and flushed DNS cache.")


_HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")
_HOSTS_BEGIN = "# >>> KIDGATE-MANAGED-START >>>"
_HOSTS_END = "# <<< KIDGATE-MANAGED-END <<<"


def sync_windows_hosts_blocklist(blocked_domains: set[str], allowed_domains: set[str] | None = None) -> None:
    """Sync blocked domains into the Windows hosts file (managed section) so browsers cannot bypass via IPv6/cache."""
    if sys.platform != "win32" or not is_windows_admin():
        return
    allowed = {d.strip().lower().rstrip(".") for d in (allowed_domains or set()) if d.strip()}
    effective = sorted(
        {d.strip().lower().rstrip(".") for d in blocked_domains if d.strip()} - allowed
    )
    try:
        existing = _HOSTS_PATH.read_text(encoding="utf-8", errors="ignore") if _HOSTS_PATH.exists() else ""
        cleaned = _strip_managed_hosts_block(existing)
        if effective:
            lines = [_HOSTS_BEGIN]
            for dom in effective:
                lines.append(f"0.0.0.0 {dom}")
                lines.append(f"0.0.0.0 www.{dom}")
                lines.append(f"0.0.0.0 m.{dom}")
                lines.append(f":: {dom}")
                lines.append(f":: www.{dom}")
                lines.append(f":: m.{dom}")
            lines.append(_HOSTS_END)
            new_content = cleaned.rstrip() + "\n\n" + "\n".join(lines) + "\n"
        else:
            new_content = cleaned
        _HOSTS_PATH.write_text(new_content, encoding="utf-8")
        flush_windows_dns_cache()
        logger.info("Synced %d blocked domain(s) to Windows hosts file.", len(effective))
    except Exception as exc:
        logger.warning("Could not sync Windows hosts file: %s", exc)


def clear_windows_hosts_blocklist() -> None:
    """Remove the KidGate-managed block from the Windows hosts file on Agent stop."""
    if sys.platform != "win32" or not is_windows_admin():
        return
    try:
        if not _HOSTS_PATH.exists():
            return
        existing = _HOSTS_PATH.read_text(encoding="utf-8", errors="ignore")
        cleaned = _strip_managed_hosts_block(existing)
        if cleaned != existing:
            _HOSTS_PATH.write_text(cleaned, encoding="utf-8")
            flush_windows_dns_cache()
            logger.info("Cleared KidGate entries from Windows hosts file.")
    except Exception as exc:
        logger.warning("Could not clear Windows hosts file: %s", exc)


def _strip_managed_hosts_block(content: str) -> str:
    lines = content.splitlines()
    out: list[str] = []
    inside = False
    for line in lines:
        if line.strip() == _HOSTS_BEGIN:
            inside = True
            continue
        if line.strip() == _HOSTS_END:
            inside = False
            continue
        if not inside:
            out.append(line)
    return "\n".join(out).rstrip() + "\n"
