"""User-Session Tray UI for KidGate Agent (`pystray` + `tkinter`).

Provides:
- System tray icon with remaining time tooltip and bilingual menu (Vietnamese / English)
- "Request more time" dialog
- Blocking reason and screen-time warning notifications
- Activity view: "What I used today" and read-only Audit Log
- Watchdog heartbeat to the Windows Service (`/ipc/tray-heartbeat`, `/ipc/tray-failed`)
"""

from __future__ import annotations

import logging
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
from typing import Any

import httpx
import pystray
from PIL import Image, ImageDraw

from agent.src.config import AgentConfig
from agent.src.storage.db import AgentLocalDB
from agent.src.storage.repository import AgentRepository
from agent.src.tray.i18n import load_tray_language, save_tray_language, tray_t

logger = logging.getLogger("ogk.tray")


def _create_tray_icon_image() -> Image.Image:
    """Create a visible 64x64 shield icon for the Windows System Tray."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([4, 4, 60, 60], radius=14, fill=(79, 70, 229, 255))
    draw.ellipse([18, 16, 46, 44], fill=(255, 255, 255, 255))
    draw.ellipse([24, 22, 40, 38], fill=(79, 70, 229, 255))
    return img


class OGKTrayApp:
    """User-session Tray UI communicating with the KidGate Agent Service via 127.0.0.1 IPC."""

    def __init__(self, config: AgentConfig, ipc_token: str) -> None:
        self.config = config
        self.ipc_token = ipc_token
        self.base_url = f"http://{config.ipc_host}:{config.ipc_port}"
        self._stop_event = threading.Event()
        self.lang: str = load_tray_language()
        self._last_online: bool = False
        self._last_rem_min: float = 0.0
        self._remaining_text: str = tray_t(self.lang, "connecting")
        self._icon: pystray.Icon | None = None

    def _t(self, key: str, **kwargs: object) -> str:
        return tray_t(self.lang, key, **kwargs)

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
        def _run() -> None:
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            if level in ("warning", "error"):
                messagebox.showwarning(f"KidGate — {title}", message, parent=root)
            else:
                messagebox.showinfo(f"KidGate — {title}", message, parent=root)
            root.destroy()

        threading.Thread(target=_run, daemon=True).start()

    def _toggle_language(self, _icon=None, _item=None) -> None:
        self.lang = "vi" if self.lang == "en" else "en"
        save_tray_language(self.lang)
        state = self._t("online") if self._last_online else self._t("offline")
        self._remaining_text = self._t("status_tooltip", state=state, mins=self._last_rem_min)
        if self._icon is not None:
            self._icon.title = self._remaining_text
            try:
                self._icon.update_menu()
            except Exception:
                pass
        self._show_popup(self._t("lang_switched_title"), self._t("lang_switched_msg"), "info")

    def _open_request_time_dialog(self, _icon=None, _item=None) -> None:
        def _run() -> None:
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            reason = simpledialog.askstring(
                self._t("req_dialog_title"),
                self._t("req_dialog_prompt"),
                parent=root,
            )
            root.destroy()
            if reason is None:
                return
            try:
                res = self._ipc_post("/ipc/request-time", {"requested_minutes": 15, "reason": reason})
                status_msg = (
                    self._t("req_sent_ok")
                    if res.get("status") == "sent"
                    else self._t("req_sent_offline")
                )
                self._show_popup(self._t("req_sent_title"), status_msg, "info")
            except Exception as exc:
                self._show_popup(self._t("err_title"), self._t("err_send", err=exc), "error")

        threading.Thread(target=_run, daemon=True).start()

    def _open_transparency_window(self, _icon=None, _item=None) -> None:
        """Open 'What I used today' + read-only Audit Log window in the chosen language."""
        def _run() -> None:
            try:
                data = self._ipc_get("/ipc/today")
            except Exception as exc:
                self._show_popup(
                    self._t("offline_title"),
                    self._t("err_load_today", err=exc),
                    "warning",
                )
                return

            win = tk.Tk()
            win.title(self._t("win_title"))
            win.geometry("640x520")

            header = tk.Label(
                win,
                text=self._t("win_header"),
                font=("Segoe UI", 13, "bold"),
                pady=8,
            )
            header.pack(fill=tk.X)

            sub = tk.Label(
                win,
                text=self._t("win_sub"),
                font=("Segoe UI", 9),
                fg="#475569",
            )
            sub.pack(fill=tk.X)

            box = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 10), padx=10, pady=10)
            box.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

            lines: list[str] = [self._t("sec_date", date=data.get("date", "")), "", self._t("sec_apps")]
            apps = data.get("apps_used", [])
            if apps:
                for a in apps:
                    lines.append(f"  - {a['name']}: {a['minutes']} {self._t('unit_min')}")
            else:
                lines.append(self._t("sec_apps_empty"))

            lines.extend(["", self._t("sec_sites")])
            sites = data.get("websites_visited", [])
            if sites:
                for s in sites:
                    lines.append(f"  - {s['domain']} ({s['visits']} {self._t('unit_visits')})")
            else:
                lines.append(self._t("sec_sites_empty"))

            lines.extend(["", self._t("sec_blocked")])
            blocked = data.get("blocked_items", [])
            if blocked:
                for b in blocked:
                    lines.append(f"  - [{b['time']}] {b['kind']}: {b['name']}")
            else:
                lines.append(self._t("sec_blocked_empty"))

            lines.extend(["", self._t("sec_audit")])
            audits = data.get("audit_logs", [])
            if audits:
                for log in audits[:20]:
                    lines.append(
                        f"  - [{str(log.get('timestamp', ''))[:19]}] {log.get('actor_email')} -> {log.get('action')}"
                    )
            else:
                lines.append(self._t("sec_audit_empty"))

            box.insert(tk.END, "\n".join(lines))
            box.configure(state=tk.DISABLED)
            win.mainloop()

        threading.Thread(target=_run, daemon=True).start()

    def _format_hms(self, total_sec: int) -> str:
        s = max(0, int(total_sec))
        hrs, rem = divmod(s, 3600)
        mins, secs = divmod(rem, 60)
        return f"{hrs:02d}:{mins:02d}:{secs:02d}"

    def _poll_loop(self) -> None:
        hb_counter = 0
        while not self._stop_event.is_set():
            try:
                if hb_counter % 10 == 0:
                    self._ipc_post("/ipc/tray-heartbeat")
                hb_counter += 1

                st = self._ipc_get("/ipc/status")
                rem_sec = int(st.get("remaining_seconds", st.get("remaining_sec", 0)))
                self._last_rem_min = round(rem_sec / 60, 1)
                self._last_online = bool(st.get("online"))
                state = self._t("online") if self._last_online else self._t("offline")
                hms = self._format_hms(rem_sec)
                self._remaining_text = f"KidGate ({state}) — {hms}"
                if self._icon is not None:
                    self._icon.title = self._remaining_text

                for notif in st.get("notifications", []):
                    self._show_popup(
                        notif.get("title", "Notice"),
                        notif.get("message", ""),
                        notif.get("level", "info"),
                    )
            except Exception as exc:
                logger.debug("Tray IPC poll failed: %s", exc)
            self._stop_event.wait(timeout=1.0)

    def run(self) -> None:
        """Start visible System Tray icon. On failure, notify Service to self-terminate."""
        try:
            menu = pystray.Menu(
                pystray.MenuItem(lambda _item: self._remaining_text, None, enabled=False),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(lambda _item: self._t("menu_today"), self._open_transparency_window),
                pystray.MenuItem(lambda _item: self._t("menu_request_time"), self._open_request_time_dialog),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(lambda _item: self._t("menu_language"), self._toggle_language),
            )
            self._icon = pystray.Icon(
                "KidGate",
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
        print("KidGate Agent is not enrolled yet. Run `python -m agent.scripts.enroll` first.")
        return
    app = OGKTrayApp(cfg, ipc_token=identity["local_ipc_token"])
    app.run()


if __name__ == "__main__":
    main()
