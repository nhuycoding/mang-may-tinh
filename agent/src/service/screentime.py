"""F1: Anti-Tamper Screen-Time Manager (monotonic clock, GetLastInputInfo, 7x48 schedule, grace period, offline expiry)."""

from __future__ import annotations

import ctypes
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable


class _LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]


def get_windows_idle_seconds() -> float:
    """Return user idle duration in seconds via Windows `GetLastInputInfo`."""
    if sys.platform != "win32":
        return 0.0
    try:
        lii = _LASTINPUTINFO()
        lii.cbSize = ctypes.sizeof(_LASTINPUTINFO)
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
            tick_count = ctypes.windll.kernel32.GetTickCount()
            elapsed_ms = (tick_count - lii.dwTime) & 0xFFFFFFFF
            return elapsed_ms / 1000.0
    except Exception:
        pass
    return 0.0


def is_workstation_locked() -> bool:
    """Best-effort check whether the Windows interactive desktop is currently locked."""
    if sys.platform != "win32":
        return False
    try:
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        return hwnd == 0
    except Exception:
        return False


def lock_windows_workstation() -> bool:
    """Invoke Windows `LockWorkStation()` API."""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.user32.LockWorkStation())
    except Exception:
        return False


@dataclass
class TickResult:
    """Outcome of a single screen-time evaluation tick."""

    used_sec: int
    effective_quota_sec: int
    remaining_sec: int
    should_lock: bool = False
    lock_reason: str = ""
    warnings: list[str] = field(default_factory=list)
    clock_tamper_detected: bool = False
    clock_tamper_reason: str = ""
    offline_policy_expired: bool = False


class ScreenTimeEngine:
    """Deterministic, anti-tamper screen-time state machine.

    Uses `time.monotonic()` for local elapsed seconds combined with `server_time` anchoring
    so rolling back the OS wall clock NEVER restores quota and immediately flags tampering.
    """

    def __init__(
        self,
        *,
        monotonic_fn: Callable[[], float] = time.monotonic,
        wall_time_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        idle_sec_fn: Callable[[], float] = get_windows_idle_seconds,
        locked_fn: Callable[[], bool] = is_workstation_locked,
    ) -> None:
        self._monotonic = monotonic_fn
        self._wall_time = wall_time_fn
        self._idle_sec = idle_sec_fn
        self._is_locked = locked_fn

        self.used_sec: float = 0.0
        self.bonus_sec: int = 0
        self.usage_date: str = self._wall_time().strftime("%Y-%m-%d")

        self._last_mono: float = self._monotonic()
        self._last_wall: datetime = self._wall_time()

        # Trusted server-time anchor: trusted_now = anchor_server_time + (mono - anchor_mono)
        self._anchor_server_time: datetime | None = None
        self._anchor_mono: float | None = None

        self.tamper_detected_count: int = 0
        self._warned_thresholds: set[int] = set()  # {600, 300, 60}
        self._grace_started_mono: float | None = None
        self.force_locked: bool = False

    def load_persisted_state(self, used_sec: int, bonus_sec: int, usage_date: str) -> None:
        self.used_sec = float(max(0, used_sec))
        self.bonus_sec = max(0, bonus_sec)
        self.usage_date = usage_date
        self._last_mono = self._monotonic()
        self._last_wall = self._wall_time()

    def anchor_server_time(self, server_time: datetime) -> bool:
        """Anchor trusted clock to `server_time`. Returns True if OS wall-clock skew > 120s."""
        if server_time.tzinfo is None:
            server_time = server_time.replace(tzinfo=timezone.utc)
        now_mono = self._monotonic()
        now_wall = self._wall_time()

        self._anchor_server_time = server_time
        self._anchor_mono = now_mono

        skew = abs((now_wall - server_time).total_seconds())
        if skew > 120:
            self.tamper_detected_count += 1
            return True
        return False

    def trusted_now(self) -> datetime:
        """Return current trusted UTC time derived from server anchor + monotonic elapsed time."""
        if self._anchor_server_time is not None and self._anchor_mono is not None:
            elapsed = max(0.0, self._monotonic() - self._anchor_mono)
            return self._anchor_server_time + timedelta(seconds=elapsed)
        return self._wall_time()

    def add_bonus_minutes(self, minutes: int) -> None:
        """Apply `add_15_mins` (or custom) override from parent."""
        self.bonus_sec += max(0, minutes) * 60
        self._grace_started_mono = None
        self.force_locked = False
        # Re-arm warnings below the new remaining threshold
        self._warned_thresholds.clear()

    def is_schedule_allowed(self, policy_payload: dict[str, Any], dt: datetime) -> bool:
        """Evaluate 7x48 weekly schedule matrix (Mon=0..Sun=6, 48 30-min slots)."""
        matrix = policy_payload.get("weekly_schedule")
        if not matrix or len(matrix) != 7:
            return True
        day_idx = dt.weekday()
        slot_idx = dt.hour * 2 + (1 if dt.minute >= 30 else 0)
        day_row = matrix[day_idx]
        if len(day_row) != 48:
            return True
        return bool(day_row[slot_idx])

    def check_offline_expiry(
        self,
        policy_payload: dict[str, Any],
        last_verified_server_time_iso: str | None,
    ) -> tuple[bool, str]:
        """Check whether offline policy has exceeded `offline_expiry_days`."""
        if not last_verified_server_time_iso:
            return False, ""
        try:
            last_srv = datetime.fromisoformat(last_verified_server_time_iso)
            if last_srv.tzinfo is None:
                last_srv = last_srv.replace(tzinfo=timezone.utc)
        except Exception:
            return False, ""

        expiry_days = int(policy_payload.get("offline_expiry_days", 3))
        mode = str(policy_payload.get("offline_expiry_mode", "fail_closed"))
        offline_age = self.trusted_now() - last_srv
        if offline_age > timedelta(days=expiry_days):
            return True, mode
        return False, mode

    def tick(
        self,
        policy_payload: dict[str, Any],
        last_verified_server_time_iso: str | None = None,
    ) -> TickResult:
        """Advance screen-time tracking using `time.monotonic()` and evaluate enforcement rules."""
        now_mono = self._monotonic()
        now_wall = self._wall_time()
        delta_mono = max(0.0, now_mono - self._last_mono)
        delta_wall = (now_wall - self._last_wall).total_seconds()

        self._last_mono = now_mono
        self._last_wall = now_wall

        tamper_detected = False
        tamper_reason = ""

        # Anti-clock tampering: detect OS wall clock rollback or large jump (> 120s divergence from monotonic)
        if delta_wall < -60.0 or abs(delta_wall - delta_mono) > 120.0:
            tamper_detected = True
            tamper_reason = f"OS clock jump detected (wall_delta={int(delta_wall)}s vs mono_delta={int(delta_mono)}s)"
            self.tamper_detected_count += 1

        trusted_dt = self.trusted_now()
        trusted_date = trusted_dt.strftime("%Y-%m-%d")
        # Only reset daily quota when the TRUSTED clock advances to a strictly newer date (never on rollback!)
        if trusted_date > self.usage_date:
            self.usage_date = trusted_date
            self.used_sec = 0.0
            self.bonus_sec = 0
            self._warned_thresholds.clear()
            self._grace_started_mono = None
            self.force_locked = False

        # Check offline policy expiration
        expired, expiry_mode = self.check_offline_expiry(policy_payload, last_verified_server_time_iso)

        # Daily quota: weekday vs weekend
        is_weekend = trusted_dt.weekday() >= 5
        base_quota = int(
            policy_payload.get("weekend_quota_sec", 10800)
            if is_weekend
            else policy_payload.get("weekday_quota_sec", 7200)
        )
        effective_quota = base_quota + self.bonus_sec
        idle_timeout = int(policy_payload.get("idle_timeout_sec", 300))
        grace_period = int(policy_payload.get("grace_period_sec", 60))

        # Active usage counting: pause when locked or idle > idle_timeout_sec (5 mins default)
        idle_sec = self._idle_sec()
        locked = self._is_locked()
        if not locked and idle_sec <= idle_timeout:
            self.used_sec += delta_mono

        used_int = int(self.used_sec)
        remaining = max(0, effective_quota - used_int)
        result = TickResult(
            used_sec=used_int,
            effective_quota_sec=effective_quota,
            remaining_sec=remaining,
            clock_tamper_detected=tamper_detected,
            clock_tamper_reason=tamper_reason,
            offline_policy_expired=expired,
        )

        # Explicit offline expiry behavior
        if expired:
            if expiry_mode == "fail_open":
                return result
            result.should_lock = True
            result.lock_reason = (
                f"Offline policy expired (> {policy_payload.get('offline_expiry_days', 3)} days offline, fail_closed)."
            )
            return result

        # Force-locked by remote `lock_now` command
        if self.force_locked:
            result.should_lock = True
            result.lock_reason = "Locked remotely by parent."
            return result

        # 7x48 Schedule check (lock within 5 seconds outside allowed hours)
        if not self.is_schedule_allowed(policy_payload, trusted_dt):
            result.should_lock = True
            result.lock_reason = "Outside allowed weekly schedule hours."
            return result

        # Warnings at 10, 5, and 1 minute remaining
        for threshold_sec, label in ((600, "10 minutes"), (300, "5 minutes"), (60, "1 minute")):
            if 0 < remaining <= threshold_sec and threshold_sec not in self._warned_thresholds:
                self._warned_thresholds.add(threshold_sec)
                result.warnings.append(f"Screen-time reminder: {label} remaining today.")

        # Quota exhausted -> 60-second grace period to save work, then lock
        if remaining <= 0:
            if self._grace_started_mono is None:
                self._grace_started_mono = now_mono
                result.warnings.append(
                    f"Daily screen-time limit reached! You have {grace_period} seconds to save your work before lock."
                )
            elif (now_mono - self._grace_started_mono) >= grace_period:
                result.should_lock = True
                result.lock_reason = "Daily screen-time quota reached."
        else:
            self._grace_started_mono = None

        return result
