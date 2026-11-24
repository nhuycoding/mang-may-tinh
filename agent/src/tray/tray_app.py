"""User-Session Tray UI for OGK-Agent (`pystray` + `tkinter`).

Implements:
- Visible system tray icon with remaining time tooltip & menu (NO stealth mode)
- "Request more time" button & dialog
- Clear blocking reason & screen-time warning popups
- Transparency screen: "What I used today" + read-only Audit Log of parent changes
- MANDATORY Anti-Abuse heartbeat: sends `/ipc/tray-heartbeat` while visible; if tray icon
  cannot be displayed, notifies `/ipc/tray-failed` so the Service self-terminates.
"""

from __future__ import annotations

import logging
import threading
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
from typing import Any
from datetime import datetime, timedelta, timezone

import httpx
import pystray
from PIL import Image, ImageDraw

from agent.src.config import AgentConfig
from agent.src.storage.db import AgentLocalDB
from agent.src.storage.repository import AgentRepository

logger = logging.getLogger("ogk.tray")


def _create_tray_icon_image() -> Image.Image:
    """Create a clear, visible 64x64 shield icon for the Windows System Tray."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([4, 4, 60, 60], radius=14, fill=(79, 70, 229, 255))
    draw.ellipse([18, 16, 46, 44], fill=(255, 255, 255, 255))
    draw.ellipse([24, 22, 40, 38], fill=(79, 70, 229, 255))
    return img


class OGKTrayApp:
    """Transparent user-session companion Tray UI communicating with OGKAgent Service via 127.0.0.1 IPC."""

    def __init__(self, config: AgentConfig, ipc_token: str) -> None:
        self.config = config
        self.ipc_token = ipc_token
        self.base_url = f"http://{config.ipc_host}:{config.ipc_port}"
        self._stop_event = threading.Event()
        self._remaining_text = "OGK Companion: Connecting..."
        self._icon: pystray.Icon | None = None
        self._active_popups: set[tuple[str, str]] = set()
        self._popup_lock = threading.Lock()

    def _headers(self) -> dict[str, str]:
        return {"X-OGK-IPC-Token": self.ipc_token}

    def _ipc_get(self, path: str) -> dict[str, Any]:
        with httpx.Client(timeout=4.0) as client:
            r = client.get(f"{self.base_url}{path}", headers=self._headers())
            r.raise_for_status()
            return r.json()

    def _ipc_post(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        with httpx.Client(timeout=4.0) as client:
            r = client.post(f"{self.base_url}{path}", headers=self._headers(), json=payload or {})
            r.raise_for_status()
            return r.json()

    def _show_popup(self, title: str, message: str, level: str = "info") -> None:
        key = (title, message)
        with self._popup_lock:
            if key in self._active_popups:
                return
            self._active_popups.add(key)

        def _run() -> None:
            try:
                root = tk.Tk()
                root.withdraw()
                root.attributes("-topmost", True)
                if level in ("warning", "error"):
                    messagebox.showwarning(f"OGK — {title}", message, parent=root)
                else:
                    messagebox.showinfo(f"OGK — {title}", message, parent=root)
                root.destroy()
            finally:
                with self._popup_lock:
                    self._active_popups.discard(key)

        threading.Thread(target=_run, daemon=True).start()

    def _open_request_time_dialog(self, _icon=None, _item=None) -> None:
        def _run() -> None:
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            reason = simpledialog.askstring(
                "Request More Time",
                "Why do you need +15 extra minutes? (e.g., finishing homework)",
                parent=root,
            )
            root.destroy()
            if reason is None:
                return
            try:
                res = self._ipc_post("/ipc/request-time", {"requested_minutes": 15, "reason": reason})
                status_msg = (
                    "Your request for +15 minutes was sent to your parent!"
                    if res.get("status") == "sent"
                    else "You are offline. Your request was saved and will be sent when back online."
                )
                self._show_popup("Time Request", status_msg, "info")
            except Exception as exc:
                self._show_popup("Error", f"Could not send request: {exc}", "error")

        threading.Thread(target=_run, daemon=True).start()

    def _open_transparency_window(self, _icon=None, _item=None) -> None:
        """Open child-friendly 'What I used today' + read-only Audit Log window."""
        def _run() -> None:
            try:
                data = self._ipc_get("/ipc/today")
            except Exception as exc:
                self._show_popup("Offline", f"Could not load today's summary: {exc}", "warning")
                return

            win = tk.Tk()
            win.title("OGK — What I Used Today & Parent Changes")
            win.geometry("640x520")

            header = tk.Label(
                win,
                text="OGK Companion — What I Used Today (Transparent View)",
                font=("Segoe UI", 13, "bold"),
                pady=8,
            )
            header.pack(fill=tk.X)

            sub = tk.Label(
                win,
                text="No hidden tracking. Only app names & main website names are shown.",
                font=("Segoe UI", 9),
                fg="#475569",
            )
            sub.pack(fill=tk.X)

            box = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 10), padx=10, pady=10)
            box.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

            lines: list[str] = [f"Date: {data.get('date', 'Today')}", "", "=== APPS I USED TODAY ==="]
            apps = data.get("apps_used", [])
            if apps:
                for a in apps:
                    lines.append(f"  - {a['name']}: {a['minutes']} min")
            else:
                lines.append("  (No app usage recorded yet today)")

            lines.extend(["", "=== WEBSITES VISITED (MAIN DOMAIN ONLY) ==="])
            sites = data.get("websites_visited", [])
            if sites:
                for s in sites:
                    lines.append(f"  - {s['domain']} ({s['visits']} visits)")
            else:
                lines.append("  (No website visits recorded yet today)")

            lines.extend(["", "=== BLOCKED ITEMS TODAY ==="])
            blocked = data.get("blocked_items", [])
            if blocked:
                for b in blocked:
                    lines.append(f"  - [{b['time']}] {b['kind']}: {b['name']}")
            else:
                lines.append("  (Nothing blocked today)")

            lines.extend(["", "=== PARENT RULE CHANGES (READ-ONLY AUDIT LOG) ==="])
            audits = data.get("audit_logs", [])
            if audits:
                vn_tz = timezone(timedelta(hours=7))
            if audits:
                for log in audits[:20]:
                    raw_ts = str(log.get("timestamp", ""))
                    try:
                        dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        ts_str = dt.astimezone(vn_tz).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        ts_str = raw_ts[:19]
                    lines.append(
                        f"  - [{ts_str}] {log.get('actor_email')} -> {log.get('action')}"
                    )
            else:
                lines.append("  (No rule changes recorded)")

            box.insert(tk.END, "\n".join(lines))
            box.configure(state=tk.DISABLED)
            win.mainloop()

        threading.Thread(target=_run, daemon=True).start()

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                # 1. Confirm to Service that Tray UI is visible & responsive (Anti-Abuse rule)
                self._ipc_post("/ipc/tray-heartbeat")

                # 2. Fetch status & display any blocking/warning popups
                st = self._ipc_get("/ipc/status")
                rem_min = round(st.get("remaining_sec", 0) / 60, 1)
                online_str = "Online" if st.get("online") else "Offline"
                self._remaining_text = f"OGK ({online_str}) — {rem_min} min left today"
                if self._icon is not None:
                    self._icon.title = self._remaining_text
                    self._icon.update_menu()

                for notif in st.get("notifications", []):
                    self._show_popup(
                        notif.get("title", "Notice"),
                        notif.get("message", ""),
                        notif.get("level", "info"),
                    )
            except Exception as exc:
                logger.debug("Tray IPC poll failed: %s", exc)
            self._stop_event.wait(timeout=10.0)

    def run(self) -> None:
        """Start visible System Tray icon. On failure, notify Service to self-terminate (Anti-Abuse)."""
        try:
            menu = pystray.Menu(
                pystray.MenuItem(lambda _item: self._remaining_text, None, enabled=False),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("What I used today && Audit Log", self._open_transparency_window),
                pystray.MenuItem("Request more time (+15 min)", self._open_request_time_dialog),
            )
            self._icon = pystray.Icon(
                "OGKCompanion",
                _create_tray_icon_image(),
                self._remaining_text,
                menu=menu,
            )
            poll_thread = threading.Thread(target=self._poll_loop, name="ogk-tray-poll", daemon=True)
            poll_thread.start()
            self._icon.run()
        except Exception as exc:
            logger.error("Failed to display Tray UI icon: %s", exc)
            try:
                self._ipc_post("/ipc/tray-failed", {"reason": str(exc)})
            except Exception:
                pass
            raise
        finally:
            self._stop_event.set()


def main() -> None:
    cfg = AgentConfig.from_env()
    repo = AgentRepository(AgentLocalDB(cfg.db_path))
    identity = repo.get_identity()
    if identity is None:
        print("OGK-Agent is not enrolled yet. Run `python -m agent.scripts.enroll` first.")
        return
    app = OGKTrayApp(cfg, ipc_token=identity["local_ipc_token"])
    app.run()


if __name__ == "__main__":
    main()
