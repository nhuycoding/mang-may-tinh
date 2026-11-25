"""KidGate Agent CLI Runner (`python -m agent.main --console`).

Provides an easy Administrator Console Testing Mode that:
- Runs the full KidGate AgentCore engine (1s Screen-Time Counter, SHA-256 App Controller,
  Real Process Usage Tracker, Local DNS Proxy on 127.0.0.1:53 + Windows DNS binding,
  WebSocket real-time policy/command listener, 60s heartbeat + offline sync)
- Automatically spawns and connects the Windows System Tray UI (`agent.src.tray.tray_app`)
- Cleanly restores Windows DNS and terminates the Tray UI on Ctrl+C
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys

from agent.src.config import AgentConfig
from agent.src.service.agent_core import AgentCore
from agent.src.service.network_dns import is_windows_admin

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ogk.main")


def main() -> None:
    parser = argparse.ArgumentParser(description="KidGate Agent Runner")
    parser.add_argument(
        "--console",
        action="store_true",
        help="Run AgentCore directly in the current Administrator terminal with Tray UI.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate workstation lock with a dismissible full-screen overlay instead of calling LockWorkStation().",
    )
    parser.add_argument("--no-dns", action="store_true", help="Disable Local DNS Proxy (127.0.0.1:53).")
    parser.add_argument("--no-tray", action="store_true", help="Do not auto-spawn the Windows Tray UI.")
    parser.add_argument("--no-watchdog", action="store_true", help="Disable Tray UI anti-abuse watchdog.")
    args = parser.parse_args()

    if not args.console:
        print("Usage: python -m agent.main --console [--dry-run] [--no-dns] [--no-tray] [--no-watchdog]")
        print("For Windows Service installation, use: python -m agent.src.service.windows_service install")
        sys.exit(0)

    cfg = AgentConfig.from_env(dry_run=True if args.dry_run else None)
    enable_watchdog = (not args.no_watchdog) and (not args.no_tray)
    core = AgentCore(
        cfg,
        enable_dns=not args.no_dns,
        enable_tray_watchdog=enable_watchdog,
        dry_run=cfg.dry_run,
    )

    tray_proc: subprocess.Popen | None = None
    if not args.no_tray:
        try:
            tray_proc = subprocess.Popen([sys.executable, "-m", "agent.src.tray.tray_app"])
            logger.info("Spawned KidGate Tray UI (PID %d).", tray_proc.pid)
        except Exception as exc:
            logger.warning("Could not auto-spawn Tray UI: %s", exc)

    try:
        mode_note = " [DRY-RUN: simulated lock overlay]" if cfg.dry_run else ""
        if not args.no_dns and sys.platform == "win32" and not is_windows_admin():
            logger.warning(
                "========================================================================\n"
                "WARNING: KidGate Agent is NOT running as Administrator!\n"
                "Windows Wi-Fi/Ethernet DNS cannot be pointed to 127.0.0.1 without Admin.\n"
                "Browser traffic will bypass KidGate DNS filtering & website tracking.\n"
                "FIX: Close this window, right-click PowerShell/Terminal -> Run as Administrator,\n"
                "     and run: python -m agent.main --console --dry-run\n"
                "========================================================================"
            )
        logger.info("Starting KidGate Agent in Administrator Console Mode%s (Ctrl+C to stop)...", mode_note)
        core.start()
    except KeyboardInterrupt:
        logger.info("Stopping KidGate Agent...")
        core.stop()
    finally:
        if tray_proc is not None and tray_proc.poll() is None:
            try:
                tray_proc.terminate()
                tray_proc.wait(timeout=3.0)
            except Exception:
                try:
                    tray_proc.kill()
                except Exception:
                    pass


if __name__ == "__main__":
    main()
