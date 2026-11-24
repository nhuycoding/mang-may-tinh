"""Authenticated 127.0.0.1 HTTP IPC bridge between Windows Service and User-Session Tray UI."""

from __future__ import annotations

import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable


class LocalIPCServer:
    """Lightweight 127.0.0.1 HTTP server authenticated with `X-OGK-IPC-Token`."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        auth_token: str,
        get_status_fn: Callable[[], dict[str, Any]],
        get_today_fn: Callable[[], dict[str, Any]],
        on_request_time_fn: Callable[[int, str], dict[str, Any]],
        on_tray_heartbeat_fn: Callable[[], None],
        on_tray_failed_fn: Callable[[str], None],
    ) -> None:
        self.host = host
        self.port = port
        self.auth_token = auth_token
        self._get_status = get_status_fn
        self._get_today = get_today_fn
        self._on_request_time = on_request_time_fn
        self._on_tray_heartbeat = on_tray_heartbeat_fn
        self._on_tray_failed = on_tray_failed_fn

        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _check_auth(self) -> bool:
                token = self.headers.get("X-OGK-IPC-Token", "")
                if not token or not hmac.compare_digest(token, parent.auth_token):
                    self._send_json(401, {"detail": "Invalid local IPC token."})
                    return False
                return True

            def _send_json(self, code: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read_json(self) -> dict[str, Any]:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0:
                    return {}
                raw = self.rfile.read(length)
                return json.loads(raw.decode("utf-8"))

            def do_GET(self) -> None:
                if not self._check_auth():
                    return
                if self.path == "/ipc/status":
                    self._send_json(200, parent._get_status())
                elif self.path == "/ipc/today":
                    self._send_json(200, parent._get_today())
                else:
                    self._send_json(404, {"detail": "Not found"})

            def do_POST(self) -> None:
                if not self._check_auth():
                    return
                if self.path == "/ipc/tray-heartbeat":
                    parent._on_tray_heartbeat()
                    self._send_json(200, {"status": "ok"})
                elif self.path == "/ipc/tray-failed":
                    body = self._read_json()
                    parent._on_tray_failed(str(body.get("reason", "Tray icon unavailable")))
                    self._send_json(200, {"status": "terminating"})
                elif self.path == "/ipc/request-time":
                    body = self._read_json()
                    minutes = int(body.get("requested_minutes", 15))
                    reason = str(body.get("reason", ""))
                    res = parent._on_request_time(minutes, reason)
                    self._send_json(200, res)
                else:
                    self._send_json(404, {"detail": "Not found"})

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, name="ogk-ipc", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
