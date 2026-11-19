"""WebSocket connection manager for pushing urgent commands (< 5s latency)."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import WebSocket


class DeviceWebSocketManager:
    """Tracks active WebSocket connections keyed by device_id."""

    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()

    async def connect(self, device_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[device_id] = websocket

    async def disconnect(self, device_id: str, websocket: WebSocket | None = None) -> None:
        async with self._lock:
            existing = self._connections.get(device_id)
            if existing is not None and (websocket is None or existing is websocket):
                self._connections.pop(device_id, None)

    def is_connected(self, device_id: str) -> bool:
        return device_id in self._connections

    async def push_command(self, device_id: str, message: dict[str, Any]) -> bool:
        """Push a JSON command message to a connected Agent. Returns True if delivered."""
        ws = self._connections.get(device_id)
        if ws is None:
            return False
        try:
            await ws.send_json(message)
            return True
        except Exception:
            await self.disconnect(device_id, ws)
            return False


ws_manager = DeviceWebSocketManager()
