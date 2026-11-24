"""F2: Application Controller matching BOTH process name AND executable SHA-256 hash."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil


@dataclass(frozen=True)
class BlockedProcessEvent:
    pid: int
    process_name: str
    exe_path: str
    sha256: str
    reason: str
    matched_by: str  # "sha256" or "name"


def compute_file_sha256(file_path: str | Path) -> str:
    """Compute SHA-256 hex digest of an executable file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower()


class AppController:
    """Enforces allow/block application rules by process name AND executable SHA-256 hash.

    Because SHA-256 is computed on the executable binary, renaming `notepad.exe` to `game.exe`
    is still accurately detected and blocked.
    """

    def __init__(self) -> None:
        # Cache: exe_path -> (mtime_ns, file_size, sha256_hex)
        self._hash_cache: dict[str, tuple[int, int, str]] = {}

    def get_cached_sha256(self, exe_path: str) -> str:
        """Compute and cache SHA-256 for `exe_path`, invalidating if mtime or size changes."""
        if not exe_path:
            return ""
        try:
            p = Path(exe_path)
            st = p.stat()
            cached = self._hash_cache.get(exe_path)
            if cached and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
                return cached[2]
            digest = compute_file_sha256(p)
            self._hash_cache[exe_path] = (st.st_mtime_ns, st.st_size, digest)
            return digest
        except (OSError, PermissionError):
            return ""

    def evaluate_process(
        self,
        process_name: str,
        exe_path: str,
        app_rules: list[dict[str, Any]],
        sha256_override: str | None = None,
    ) -> tuple[bool, str, str]:
        """Evaluate a process against policy `app_rules`.

        Returns `(is_blocked, reason, matched_by)`.
        Explicit `allow` rule matching SHA-256 or name takes precedence over `block`.
        """
        proc_lower = process_name.strip().lower()
        exe_sha = sha256_override.lower() if sha256_override is not None else self.get_cached_sha256(exe_path)

        # First check explicit allow rules
        for rule in app_rules:
            if rule.get("action") != "allow":
                continue
            r_sha = (rule.get("sha256") or "").strip().lower()
            r_name = (rule.get("name") or "").strip().lower()
            if (r_sha and exe_sha and r_sha == exe_sha) or (r_name and r_name == proc_lower):
                return False, "", ""

        # Then check block rules (SHA-256 match catches renamed executables!)
        for rule in app_rules:
            if rule.get("action") != "block":
                continue
            r_sha = (rule.get("sha256") or "").strip().lower()
            r_name = (rule.get("name") or "").strip().lower()
            reason = rule.get("reason") or f"Application '{process_name}' is blocked by family policy."

            if r_sha and exe_sha and r_sha == exe_sha:
                return True, reason, "sha256"
            if r_name and r_name == proc_lower:
                return True, reason, "name"

        return False, "", ""

    def scan_and_enforce(
        self,
        app_rules: list[dict[str, Any]],
        *,
        terminate: bool = True,
    ) -> list[BlockedProcessEvent]:
        """Scan running processes, terminate blocked ones via psutil, and return blocked events."""
        if not app_rules:
            return []

        blocked_events: list[BlockedProcessEvent] = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = proc.info
                pid = info.get("pid")
                name = info.get("name") or ""
                exe = info.get("exe") or ""
                if not name or pid in (0, 4):
                    continue

                is_blocked, reason, matched_by = self.evaluate_process(name, exe, app_rules)
                if not is_blocked:
                    continue

                exe_sha = self.get_cached_sha256(exe)
                if terminate:
                    try:
                        proc.terminate()
                        proc.wait(timeout=2.0)
                    except psutil.TimeoutExpired:
                        proc.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                blocked_events.append(
                    BlockedProcessEvent(
                        pid=int(pid),
                        process_name=name,
                        exe_path=exe,
                        sha256=exe_sha,
                        reason=reason,
                        matched_by=matched_by,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return blocked_events
