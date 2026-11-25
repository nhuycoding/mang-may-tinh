"""OGK-Agent Service Core Orchestrator.

Coordinates:
- Local SQLite WAL repository & offline event queue
- F1 Anti-Tamper Screen-Time Engine (monotonic + server_time + GetLastInputInfo + 7x48 schedule)
- F2 SHA-256 App Controller & Local DNS Proxy (127.0.0.1:53 + SafeSearch)
- 60s Heartbeat + Offline Batch Sync (`idempotency_key`) + WebSocket Urgent Commands (< 5s)
- Local IPC Server for User-Session Tray UI
- MANDATORY Anti-Abuse Rule: self-terminates & logs if Tray UI cannot display icon or is unresponsive
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
import websockets

from agent.src.config import AgentConfig
from agent.src.service.app_controller import AppController
from agent.src.service.dns_proxy import LocalDNSProxyServer
from agent.src.service.ipc_server import LocalIPCServer
from agent.src.service.net_client import AgentNetClient, CertificatePinningError, PolicyTamperError
from agent.src.service.network_dns import (
    clear_windows_hosts_blocklist,
    configure_system_dns,
    restore_system_dns,
    sync_windows_hosts_blocklist,
)
from agent.src.service.screentime import (
    ScreenTimeEngine,
    lock_windows_workstation,
    show_dry_run_lock_overlay,
)
from agent.src.storage.db import AgentLocalDB
from agent.src.storage.repository import AgentRepository, utcnow_iso

logger = logging.getLogger("ogk.agent")


class AgentCore:
    """Main runtime engine executed inside the Windows Service (or console mode)."""

    def __init__(
        self,
        config: AgentConfig,
        *,
        enable_dns: bool = True,
        enable_tray_watchdog: bool = True,
        dry_run: bool | None = None,
    ) -> None:
        self.config = config
        self.enable_dns = enable_dns
        self.enable_tray_watchdog = enable_tray_watchdog
        self.dry_run = config.dry_run if dry_run is None else bool(dry_run)
        self._dry_run_overlay_lock = threading.Lock()
        self._dry_run_overlay_open: bool = False
        self._dry_run_dismissed_condition: str | None = None

        self.db = AgentLocalDB(config.db_path)
        self.repo = AgentRepository(self.db)
        self.screentime = ScreenTimeEngine()
        self.app_controller = AppController()
        self.dns_proxy: LocalDNSProxyServer | None = None
        self.ipc_server: LocalIPCServer | None = None
        self.net: AgentNetClient | None = None

        self._stop_event = threading.Event()
        self._ws_thread: threading.Thread | None = None
        self._st_thread: threading.Thread | None = None
        self._policy_lock = threading.RLock()
        self._sync_lock = threading.Lock()
        self._dns_configured_by_agent: bool = False

        self._identity: dict[str, Any] | None = None
        self._policy_payload: dict[str, Any] = {}
        self._policy_version: int = 0
        self._policy_id: int | None = None
        self._last_verified_server_time: str | None = None
        self._online: bool = False

        # Tray UI notification queue & Anti-Abuse watchdog timestamp
        self._notifications: deque[dict[str, str]] = deque(maxlen=50)
        self._notif_lock = threading.Lock()
        self._last_tray_heartbeat_mono: float = time.monotonic()
        self._tray_failed_reason: str | None = None
        self._self_terminated: bool = False

    def push_notification(self, title: str, message: str, level: str = "info") -> None:
        with self._notif_lock:
            self._notifications.append({"title": title, "message": message, "level": level, "ts": utcnow_iso()})

    def _drain_notifications(self) -> list[dict[str, str]]:
        with self._notif_lock:
            items = list(self._notifications)
            self._notifications.clear()
            return items

    def _on_dns_event(self, event_type: str, sld: str, reason: str) -> None:
        if not self._identity:
            return
        self.repo.enqueue_event(
            device_id=self._identity["device_id"],
            child_id=self._identity["child_id"],
            event_type=event_type,
            subject=sld,
            duration_sec=0,
            policy_id=self._policy_id,
        )
        if event_type == "blocked_domain":
            self.push_notification("Website Blocked", reason or f"{sld} is blocked by family policy.", "warning")

    def _apply_policy_record(self, cached: dict[str, Any]) -> None:
        with self._policy_lock:
            self._policy_id = cached["policy_id"]
            self._policy_version = cached["policy_version"]
            self._policy_payload = cached["payload"]
            self._last_verified_server_time = cached.get("last_verified_server_time")
            payload_copy = dict(self._policy_payload)
        if self.dns_proxy is not None:
            self.dns_proxy.update_policy(payload_copy)
        if self.enable_dns:
            blocked_all = set(payload_copy.get("blocked_domains", [])) | set(
                payload_copy.get("category_blocked_domains", [])
            )
            allowed_all = set(payload_copy.get("allowed_domains", []))
            sync_windows_hosts_blocklist(blocked_all, allowed_all)
        logger.info("Hot-reloaded policy v%d in memory (DNS + Hosts + App + ScreenTime).", self._policy_version)

    def _call_with_refresh(self, fn):
        try:
            return fn(self._identity["access_token"])
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                self._ensure_access_token_fresh()
                return fn(self._identity["access_token"])
            raise

    def refresh_policy_now(self) -> bool:
        """Immediately fetch GET /policy, verify HMAC-SHA256, persist to SQLite, and hot-reload in memory."""
        if not self._identity or not self.net:
            return False
        try:
            pol = self._call_with_refresh(
                lambda tok: self.net.fetch_verified_policy(tok, self._identity["hmac_secret"])
            )
            srv_time = self._last_verified_server_time or utcnow_iso()
            self.repo.save_cached_policy(
                policy_id=pol["policy_id"],
                policy_version=pol["policy_version"],
                payload_json=pol["payload_json"],
                signature_hmac=pol["signature_hmac"],
                server_time_iso=srv_time,
            )
            cached = self.repo.get_cached_policy()
            if cached:
                self._apply_policy_record(cached)
            # Immediately enforce newly added app block rules without waiting
            self._enforce_app_rules_once()
            return True
        except (CertificatePinningError, PolicyTamperError) as sec_err:
            logger.error("Policy refresh security failure: %s", sec_err)
            self.push_notification("Security Alert", str(sec_err), "error")
            return False
        except Exception as exc:
            logger.warning("Immediate policy refresh failed: %s", exc)
            return False

    def _enforce_app_rules_once(self) -> None:
        if not self._identity:
            return
        with self._policy_lock:
            app_rules = list(self._policy_payload.get("app_rules", []))
            policy_id = self._policy_id
        if not app_rules:
            return
        blocked_procs = self.app_controller.scan_and_enforce(app_rules, terminate=True)
        for bp in blocked_procs:
            self.repo.enqueue_event(
                device_id=self._identity["device_id"],
                child_id=self._identity["child_id"],
                event_type="blocked_app",
                subject=bp.process_name,
                duration_sec=0,
                policy_id=policy_id,
            )
            self.push_notification(
                "Application Blocked",
                f"{bp.process_name} was closed ({bp.reason}) [matched by {bp.matched_by}].",
                "warning",
            )

    def _ipc_get_status(self) -> dict[str, Any]:
        with self._policy_lock:
            payload = dict(self._policy_payload)
            pol_ver = self._policy_version
        is_weekend = self.screentime.trusted_now().weekday() >= 5
        quota = int(
            payload.get("weekend_quota_sec", 10800)
            if is_weekend
            else payload.get("weekday_quota_sec", 7200)
        ) + self.screentime.bonus_sec
        used = int(self.screentime.used_sec)
        remaining = max(0, quota - used)
        return {
            "device_id": self._identity["device_id"] if self._identity else "",
            "online": self._online,
            "policy_version": pol_ver,
            "used_sec": used,
            "used_seconds": used,
            "quota_sec": quota,
            "bonus_sec": self.screentime.bonus_sec,
            "remaining_sec": remaining,
            "remaining_seconds": remaining,
            "is_locked": self.screentime.is_locked,
            "is_idle": self.screentime.is_idle,
            "lock_reason": self.screentime.last_lock_reason,
            "notifications": self._drain_notifications(),
        }

    def _ipc_get_today(self) -> dict[str, Any]:
        summary = self.repo.get_today_summary(self.screentime.usage_date)
        summary["audit_logs"] = self.repo.get_audit_cache(30)
        return summary

    def _ipc_request_time(self, requested_minutes: int, reason: str) -> dict[str, Any]:
        if not self._identity or not self.net:
            return {"status": "not_enrolled"}
        try:
            res = self.net.submit_extension_request(
                self._identity["access_token"], requested_minutes=requested_minutes, reason=reason
            )
            self.push_notification("Request Sent", f"Asked parent for +{requested_minutes} minutes.", "info")
            return {"status": "sent", "request": res}
        except Exception as exc:
            self.repo.enqueue_event(
                device_id=self._identity["device_id"],
                child_id=self._identity["child_id"],
                event_type="unlock_request",
                subject=f"request_{requested_minutes}_mins",
                duration_sec=requested_minutes * 60,
                policy_id=self._policy_id,
            )
            return {"status": "queued_offline", "detail": str(exc)}

    def _ipc_tray_heartbeat(self) -> None:
        self._last_tray_heartbeat_mono = time.monotonic()

    def _ipc_tray_failed(self, reason: str) -> None:
        """MANDATORY Anti-Abuse Rule: Tray UI reported inability to display icon -> self-terminate."""
        self._tray_failed_reason = reason
        logger.error("ANTI-ABUSE TRIGGERED: Tray UI failed (%s). Self-terminating Agent.", reason)
        self._log_and_self_terminate(f"tray_failed:{reason}")

    def _log_and_self_terminate(self, reason: str) -> None:
        self._self_terminated = True
        if self._identity:
            self.repo.enqueue_event(
                device_id=self._identity["device_id"],
                child_id=self._identity["child_id"],
                event_type="locked",
                subject="agent_anti_abuse_self_terminate",
                duration_sec=0,
                policy_id=self._policy_id,
            )
        logger.critical("KidGate Agent self-terminating (Tray UI watchdog triggered): %s", reason)
        self._stop_event.set()

    def _ensure_access_token_fresh(self) -> None:
        """Refresh short-lived access_token using refresh_token on 401."""
        if not self._identity or not self.net:
            return
        refreshed = self.net.refresh_access_token(self._identity["refresh_token"])
        self._identity["access_token"] = refreshed["access_token"]
        self.repo.update_access_token(refreshed["access_token"])

    def _trigger_workstation_lock(self, reason: str, *, force_overlay: bool = False) -> None:
        """Lock Windows workstation, or show a full-screen Dry-Run overlay when `--dry-run` is active."""
        if not self.dry_run:
            lock_windows_workstation()
            return

        with self._dry_run_overlay_lock:
            if self._dry_run_overlay_open:
                return
            if not force_overlay and self._dry_run_dismissed_condition == reason:
                return
            self._dry_run_overlay_open = True
            self._dry_run_dismissed_condition = None

        logger.warning("[DRY-RUN] Simulated Workstation Lock: %s", reason)

        def _on_dismiss() -> None:
            with self._dry_run_overlay_lock:
                self._dry_run_overlay_open = False
                self._dry_run_dismissed_condition = reason
            if self.screentime.force_locked:
                self.screentime.force_locked = False
                self.screentime.is_locked = False

        threading.Thread(
            target=show_dry_run_lock_overlay,
            args=(reason, _on_dismiss),
            name="ogk-dry-run-lock",
            daemon=True,
        ).start()

    def execute_command(self, cmd: dict[str, Any]) -> None:
        """Execute an urgent command (`lock_now`, `unlock`, `add_15_mins`, `wipe_local_data`)."""
        cmd_id = cmd.get("command_id") or cmd.get("id")
        cmd_type = cmd.get("command_type")
        payload = cmd.get("payload") or {}
        logger.info("Executing remote command: %s (%s)", cmd_type, cmd_id)

        if cmd_type == "lock_now":
            self.screentime.force_locked = True
            self.screentime.is_locked = True
            self.push_notification("Device Locked", "Parent remotely locked this computer.", "warning")
            self._trigger_workstation_lock("Locked remotely by parent.", force_overlay=True)
        elif cmd_type == "unlock":
            self.screentime.force_locked = False
            self.screentime.is_locked = False
            with self._dry_run_overlay_lock:
                self._dry_run_dismissed_condition = None
            self.push_notification("Device Unlocked", "Parent unlocked this computer.", "info")
        elif cmd_type == "add_15_mins":
            mins = int(payload.get("minutes", 15))
            self.screentime.add_bonus_minutes(mins)
            self.push_notification("Extra Time Granted", f"Parent added +{mins} minutes today!", "info")
        elif cmd_type == "wipe_local_data":
            self.db.wipe_all_local_data()
            self.screentime.used_sec = 0.0
            self.screentime.bonus_sec = 0
            self.push_notification("Data Wiped", "Parent deleted local activity data.", "info")

        if cmd_id and self._identity and self.net:
            try:
                self._call_with_refresh(
                    lambda tok: self.net.ack_command(tok, cmd_id, status="acknowledged")
                )
            except Exception:
                pass
        # Sync updated state back to server immediately so Web UI reflects it
        threading.Thread(target=self._sync_with_server, name="ogk-sync-cmd", daemon=True).start()

    def _sync_with_server(self) -> None:
        """Perform 60s Heartbeat, Policy HMAC fetch if version changed, Offline Event Batch Sync, and Audit Cache."""
        if not self._identity or not self.net:
            return
        if not self._sync_lock.acquire(blocking=False):
            return
        try:
            hb = self._call_with_refresh(
                lambda tok: self.net.send_heartbeat(
                    tok,
                    status="locked" if self.screentime.is_locked else "online",
                    used_quota_sec_today=int(self.screentime.used_sec),
                    current_policy_version=self._policy_version,
                    client_time_iso=utcnow_iso(),
                    clock_tamper_detected=self.screentime.tamper_detected_count > 0,
                )
            )
            self._online = True
            srv_dt = datetime.fromisoformat(hb["server_time"])
            if srv_dt.tzinfo is None:
                srv_dt = srv_dt.replace(tzinfo=timezone.utc)
            self.screentime.anchor_server_time(srv_dt)
            self._last_verified_server_time = srv_dt.isoformat()
            self.repo.touch_last_verified_server_time(self._last_verified_server_time)

            # Fetch & HMAC-verify policy if version mismatched
            if hb.get("policy_update_required") or self._policy_version == 0:
                self.refresh_policy_now()

            # Execute any pending commands returned in heartbeat fallback
            for cmd in hb.get("pending_commands", []):
                self.execute_command(cmd)

            # Batch-sync buffered offline events using idempotency_key
            unsynced = self.repo.get_unsynced_events(limit=100)
            if unsynced:
                self._call_with_refresh(lambda tok: self.net.sync_event_batch(tok, unsynced))
                self.repo.mark_events_synced([e["id"] for e in unsynced])

            # Refresh local read-only audit log cache for Tray UI
            audit_items = self._call_with_refresh(lambda tok: self.net.fetch_audit_logs(tok))
            self.repo.replace_audit_cache(audit_items)

        except (CertificatePinningError, PolicyTamperError) as sec_err:
            self._online = False
            logger.error("Security check failed: %s", sec_err)
            self.push_notification("Security Alert", str(sec_err), "error")
        except Exception as exc:
            self._online = False
            logger.warning("Offline mode active (server unreachable): %s", exc)
        finally:
            self._sync_lock.release()

    def _run_ws_listener(self) -> None:
        """Background WebSocket listener for real-time urgent commands & policy updates (< 5s latency)."""
        async def _ws_loop() -> None:
            while not self._stop_event.is_set():
                if not self._identity:
                    await asyncio.sleep(3)
                    continue
                parsed = urlparse(self._identity["server_url"])
                ws_scheme = "wss" if parsed.scheme == "https" else "ws"
                ws_url = (
                    f"{ws_scheme}://{parsed.netloc}/commands/ws/{self._identity['device_id']}"
                    f"?token={self._identity['access_token']}"
                )
                ssl_ctx = None
                if ws_scheme == "wss":
                    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                try:
                    async with websockets.connect(ws_url, ssl=ssl_ctx, ping_interval=20) as ws:
                        logger.info("WebSocket connected to %s", parsed.netloc)
                        while not self._stop_event.is_set():
                            try:
                                raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
                            except asyncio.TimeoutError:
                                continue
                            msg = json.loads(raw)
                            msg_type = msg.get("type")
                            if msg_type == "command":
                                await asyncio.to_thread(self.execute_command, msg)
                                await ws.send(
                                    json.dumps(
                                        {
                                            "type": "ack",
                                            "command_id": msg.get("command_id"),
                                            "status": "acknowledged",
                                        }
                                    )
                                )
                            elif msg_type == "policy_updated":
                                logger.info(
                                    "Received real-time policy_updated (v%s) via WebSocket.",
                                    msg.get("policy_version"),
                                )
                                await asyncio.to_thread(self.refresh_policy_now)
                except Exception as exc:
                    logger.debug("WebSocket disconnected (%s); refreshing token & retrying...", exc)
                    try:
                        await asyncio.to_thread(self._ensure_access_token_fresh)
                    except Exception:
                        pass
                    await asyncio.sleep(4)

        asyncio.run(_ws_loop())

    def _run_screentime_loop(self) -> None:
        """Dedicated 1-second monotonic screen-time tick loop with immediate state-change sync."""
        last_persist_mono = time.monotonic()
        prev_locked = self.screentime.is_locked

        while not self._stop_event.is_set():
            now_mono = time.monotonic()
            with self._policy_lock:
                payload = dict(self._policy_payload)
                policy_id = self._policy_id
                last_srv_time = self._last_verified_server_time

            if payload and self._identity:
                tick_res = self.screentime.tick(
                    payload,
                    last_verified_server_time_iso=last_srv_time,
                )
                for warn in tick_res.warnings:
                    self.push_notification("Screen-Time Reminder", warn, "warning")
                    self.repo.enqueue_event(
                        device_id=self._identity["device_id"],
                        child_id=self._identity["child_id"],
                        event_type="quota_warning",
                        subject="quota_warning",
                        duration_sec=tick_res.remaining_sec,
                        policy_id=policy_id,
                    )
                if tick_res.clock_tamper_detected:
                    self.repo.enqueue_event(
                        device_id=self._identity["device_id"],
                        child_id=self._identity["child_id"],
                        event_type="quota_warning",
                        subject="clock_tamper_detected",
                        duration_sec=0,
                        policy_id=policy_id,
                    )
                if tick_res.should_lock:
                    self.push_notification("Workstation Locking", tick_res.lock_reason, "warning")
                    self.repo.enqueue_event(
                        device_id=self._identity["device_id"],
                        child_id=self._identity["child_id"],
                        event_type="locked",
                        subject=tick_res.lock_reason[:120],
                        duration_sec=tick_res.used_sec,
                        policy_id=policy_id,
                    )
                    self._trigger_workstation_lock(tick_res.lock_reason)
                elif self.dry_run:
                    with self._dry_run_overlay_lock:
                        self._dry_run_dismissed_condition = None

                # Persist usage every 5 seconds or immediately on lock state change
                state_changed = tick_res.is_locked != prev_locked
                prev_locked = tick_res.is_locked
                if state_changed or (now_mono - last_persist_mono) >= 5.0:
                    self.repo.save_daily_usage(
                        usage_date=self.screentime.usage_date,
                        used_sec=tick_res.used_sec,
                        bonus_sec=self.screentime.bonus_sec,
                        last_monotonic_sec=now_mono,
                        last_server_time=last_srv_time,
                        last_wall_time=utcnow_iso(),
                        tamper_detected_count=self.screentime.tamper_detected_count,
                    )
                    last_persist_mono = now_mono

                if state_changed:
                    threading.Thread(target=self._sync_with_server, name="ogk-sync-state", daemon=True).start()

            self._stop_event.wait(timeout=1.0)

    def start(self) -> None:
        """Start all Agent subsystems and enter the main enforcement loop."""
        self._identity = self.repo.get_identity()
        if self._identity is None:
            raise RuntimeError(
                "OGK-Agent is not enrolled yet. Run `python -m agent.scripts.enroll` first."
            )

        self.net = AgentNetClient(
            server_url=self._identity["server_url"],
            pinned_cert_sha256=self._identity["server_cert_sha256"],
        )

        # Load persisted daily usage & cached policy for immediate offline enforcement
        usage = self.repo.get_daily_usage(self.screentime.usage_date)
        self.screentime.load_persisted_state(
            used_sec=usage["used_sec"],
            bonus_sec=usage["bonus_sec"],
            usage_date=usage["usage_date"],
        )
        cached_policy = self.repo.get_cached_policy()
        if cached_policy:
            self._apply_policy_record(cached_policy)

        # Start authenticated 127.0.0.1 IPC server for Tray UI
        self.ipc_server = LocalIPCServer(
            host=self.config.ipc_host,
            port=self.config.ipc_port,
            auth_token=self._identity["local_ipc_token"],
            get_status_fn=self._ipc_get_status,
            get_today_fn=self._ipc_get_today,
            on_request_time_fn=self._ipc_request_time,
            on_tray_heartbeat_fn=self._ipc_tray_heartbeat,
            on_tray_failed_fn=self._ipc_tray_failed,
        )
        self.ipc_server.start()

        # Start Local DNS Proxy (127.0.0.1:53) & bind Windows network adapters if Admin/SYSTEM
        if self.enable_dns:
            self.dns_proxy = LocalDNSProxyServer(
                bind_host=self.config.dns_bind_host,
                bind_port=self.config.dns_bind_port,
                upstream_host=self.config.upstream_dns_host,
                upstream_port=self.config.upstream_dns_port,
                on_event=self._on_dns_event,
            )
            if self._policy_payload:
                self.dns_proxy.update_policy(self._policy_payload)
            try:
                self.dns_proxy.start()
                if self.config.dns_bind_port == 53:
                    configured = configure_system_dns(
                        self.config.data_dir / "original_dns.json",
                        dns_ip=self.config.dns_bind_host,
                    )
                    self._dns_configured_by_agent = bool(configured)
            except OSError as exc:
                logger.error("Could not bind Local DNS Proxy on %s:%d: %s", self.config.dns_bind_host, self.config.dns_bind_port, exc)

        # Initial server sync before starting enforcement threads
        self._sync_with_server()

        # Start WebSocket real-time listener (urgent commands + policy_updated)
        self._ws_thread = threading.Thread(target=self._run_ws_listener, name="ogk-ws", daemon=True)
        self._ws_thread.start()

        # Start dedicated 1-second screen-time counter thread
        self._st_thread = threading.Thread(target=self._run_screentime_loop, name="ogk-screentime", daemon=True)
        self._st_thread.start()

        last_hb_mono = time.monotonic()
        self._last_tray_heartbeat_mono = time.monotonic()

        # Main enforcement loop (1.5s tick for real-time app tracking & SHA-256 blocking + 60s heartbeat)
        while not self._stop_event.is_set():
            now_mono = time.monotonic()

            # MANDATORY Anti-Abuse Watchdog: no stealth mode!
            if self.enable_tray_watchdog:
                if (now_mono - self._last_tray_heartbeat_mono) > self.config.tray_watchdog_timeout_sec:
                    self._log_and_self_terminate(
                        f"Tray UI unresponsive for > {self.config.tray_watchdog_timeout_sec}s"
                    )
                    break

            # F2: Real Windows Process Tracking (Top 10 apps + What I used today) & SHA-256 App Blocking
            usage_events = self.app_controller.track_foreground_app(
                is_paused=self.screentime.is_locked or self.screentime.is_idle
            )
            for uev in usage_events:
                self.repo.enqueue_event(
                    device_id=self._identity["device_id"],
                    child_id=self._identity["child_id"],
                    event_type=uev.event_type,
                    subject=uev.app_name,
                    duration_sec=uev.duration_sec,
                    policy_id=self._policy_id,
                )

            self._enforce_app_rules_once()

            # 60s Heartbeat & Offline Batch Sync
            if (now_mono - last_hb_mono) >= self.config.heartbeat_interval_sec:
                self._sync_with_server()
                last_hb_mono = now_mono

            self._stop_event.wait(timeout=1.5)

        self.stop()

    def stop(self) -> None:
        self._stop_event.set()
        if self._identity:
            for uev in self.app_controller.flush_active_session():
                self.repo.enqueue_event(
                    device_id=self._identity["device_id"],
                    child_id=self._identity["child_id"],
                    event_type=uev.event_type,
                    subject=uev.app_name,
                    duration_sec=uev.duration_sec,
                    policy_id=self._policy_id,
                )
        if self._dns_configured_by_agent:
            restore_system_dns(self.config.data_dir / "original_dns.json")
            self._dns_configured_by_agent = False
        if self.enable_dns:
            clear_windows_hosts_blocklist()
        if self.dns_proxy is not None:
            self.dns_proxy.stop()
        if self.ipc_server is not None:
            self.ipc_server.stop()
