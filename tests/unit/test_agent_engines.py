"""Unit tests for OGK-Agent F1 Screen-Time Engine, F2 SHA-256 App Controller, and Local DNS Proxy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from dnslib import DNSRecord, QTYPE, RCODE

from agent.src.service.app_controller import AppController, compute_file_sha256
from agent.src.service.dns_proxy import OGKDNSResolver
from agent.src.service.screentime import ScreenTimeEngine


def _base_policy(**overrides):
    pol = {
        "weekday_quota_sec": 180,  # 3 minutes
        "weekend_quota_sec": 300,
        "grace_period_sec": 60,
        "idle_timeout_sec": 300,
        "offline_expiry_days": 3,
        "offline_expiry_mode": "fail_closed",
        "weekly_schedule": [[1] * 48 for _ in range(7)],
    }
    pol.update(overrides)
    return pol


def test_screentime_weekday_3min_quota_and_grace_period():
    mono = [1000.0]
    wall = [datetime(2026, 11, 19, 10, 0, 0, tzinfo=timezone.utc)]  # Thursday
    eng = ScreenTimeEngine(
        monotonic_fn=lambda: mono[0],
        wall_time_fn=lambda: wall[0],
        idle_sec_fn=lambda: 0.0,
        locked_fn=lambda: False,
    )
    eng.anchor_server_time(wall[0])
    pol = _base_policy()

    mono[0] += 120.0
    wall[0] += timedelta(seconds=120)
    r1 = eng.tick(pol)
    assert r1.used_sec == 120
    assert r1.remaining_sec == 60
    assert r1.should_lock is False
    assert any("1 minute" in w for w in r1.warnings)

    # Reach 180s -> starts 60-second grace period (not locked immediately)
    mono[0] += 60.0
    wall[0] += timedelta(seconds=60)
    r2 = eng.tick(pol)
    assert r2.remaining_sec == 0
    assert r2.should_lock is False
    assert any("60 seconds" in w for w in r2.warnings)

    # After 60s grace period -> MUST lock
    mono[0] += 60.0
    wall[0] += timedelta(seconds=60)
    r3 = eng.tick(pol)
    assert r3.should_lock is True
    assert "quota" in r3.lock_reason.lower()


def test_screentime_idle_pauses_counting():
    mono = [500.0]
    wall = [datetime(2026, 11, 19, 10, 0, 0, tzinfo=timezone.utc)]
    idle = [400.0]  # > 300s idle threshold
    eng = ScreenTimeEngine(
        monotonic_fn=lambda: mono[0],
        wall_time_fn=lambda: wall[0],
        idle_sec_fn=lambda: idle[0],
        locked_fn=lambda: False,
    )
    mono[0] += 120.0
    wall[0] += timedelta(seconds=120)
    res = eng.tick(_base_policy())
    assert res.used_sec == 0


def test_screentime_clock_rollback_3h_does_not_restore_quota():
    mono = [2000.0]
    wall = [datetime(2026, 11, 19, 14, 0, 0, tzinfo=timezone.utc)]
    eng = ScreenTimeEngine(
        monotonic_fn=lambda: mono[0],
        wall_time_fn=lambda: wall[0],
        idle_sec_fn=lambda: 0.0,
        locked_fn=lambda: False,
    )
    eng.anchor_server_time(wall[0])
    pol = _base_policy(weekday_quota_sec=600)

    mono[0] += 300.0
    wall[0] += timedelta(seconds=300)
    r1 = eng.tick(pol)
    assert r1.used_sec == 300

    # Child rolls back OS clock by 3 hours
    mono[0] += 10.0
    wall[0] -= timedelta(hours=3)
    r2 = eng.tick(pol)
    assert r2.clock_tamper_detected is True
    assert r2.used_sec == 310  # Quota NOT restored!


def test_screentime_weekly_schedule_7x48_locks_outside_allowed():
    mono = [100.0]
    wall = [datetime(2026, 11, 19, 22, 15, 0, tzinfo=timezone.utc)]  # Thursday 22:15 (slot 44)
    eng = ScreenTimeEngine(
        monotonic_fn=lambda: mono[0],
        wall_time_fn=lambda: wall[0],
        idle_sec_fn=lambda: 0.0,
        locked_fn=lambda: False,
    )
    eng.anchor_server_time(wall[0])
    # Allow only 07:00-21:00 (slots 14..41)
    schedule = [[1 if 14 <= s < 42 else 0 for s in range(48)] for _ in range(7)]
    pol = _base_policy(weekly_schedule=schedule)

    mono[0] += 2.0
    wall[0] += timedelta(seconds=2)
    res = eng.tick(pol)
    assert res.should_lock is True
    assert "schedule" in res.lock_reason.lower()


def test_screentime_offline_expiry_fail_closed_vs_fail_open():
    mono = [100.0]
    now = datetime(2026, 11, 19, 10, 0, 0, tzinfo=timezone.utc)
    five_days_ago = (now - timedelta(days=5)).isoformat()
    eng = ScreenTimeEngine(
        monotonic_fn=lambda: mono[0],
        wall_time_fn=lambda: now,
        idle_sec_fn=lambda: 0.0,
        locked_fn=lambda: False,
    )
    eng.anchor_server_time(now)

    res_closed = eng.tick(
        _base_policy(offline_expiry_days=3, offline_expiry_mode="fail_closed"),
        last_verified_server_time_iso=five_days_ago,
    )
    assert res_closed.offline_policy_expired is True
    assert res_closed.should_lock is True

    res_open = eng.tick(
        _base_policy(offline_expiry_days=3, offline_expiry_mode="fail_open"),
        last_verified_server_time_iso=five_days_ago,
    )
    assert res_open.offline_policy_expired is True
    assert res_open.should_lock is False


def test_app_controller_detects_renamed_executable_by_sha256(tmp_path: Path):
    orig = tmp_path / "notepad.exe"
    renamed = tmp_path / "game.exe"
    content = b"MZ-SIMULATED-NOTEPAD-BINARY-PAYLOAD"
    orig.write_bytes(content)
    renamed.write_bytes(content)

    sha = compute_file_sha256(orig)
    ctrl = AppController()
    rules = [{"name": "notepad.exe", "sha256": sha, "action": "block", "reason": "Blocked during study"}]

    blocked, reason, matched_by = ctrl.evaluate_process("game.exe", str(renamed), rules)
    assert blocked is True
    assert matched_by == "sha256"
    assert "study" in reason.lower()


def test_app_controller_allow_overrides_block(tmp_path: Path):
    exe = tmp_path / "calc.exe"
    exe.write_bytes(b"CALC-BINARY")
    sha = compute_file_sha256(exe)
    ctrl = AppController()
    rules = [
        {"name": "calc.exe", "sha256": sha, "action": "allow", "reason": "Allowed for math"},
        {"name": "calc.exe", "sha256": "", "action": "block", "reason": "Generic block"},
    ]
    blocked, _, _ = ctrl.evaluate_process("calc.exe", str(exe), rules)
    assert blocked is False


def test_dns_proxy_blocks_exact_and_subdomains_nxdomain():
    seen = []
    resolver = OGKDNSResolver(on_event=lambda t, s, r: seen.append((t, s, r)))
    resolver.update_policy({"blocked_domains": ["adult-sim-01.test"], "safesearch_enabled": True})

    r_exact = resolver.resolve(DNSRecord.question("adult-sim-01.test", "A"))
    r_sub = resolver.resolve(DNSRecord.question("video.cdn.adult-sim-01.test", "A"))
    assert r_exact.header.rcode == RCODE.NXDOMAIN
    assert r_sub.header.rcode == RCODE.NXDOMAIN
    assert seen[-1][0] == "blocked_domain"
    assert seen[-1][1] == "adult-sim-01.test"


def test_dns_proxy_enforces_safesearch_google_bing_ddg():
    resolver = OGKDNSResolver()
    resolver.update_policy({"safesearch_enabled": True})

    for qhost, expected_target in (
        ("www.google.com", "forcesafesearch.google.com."),
        ("www.bing.com", "strict.bing.com."),
        ("duckduckgo.com", "safe.duckduckgo.com."),
    ):
        reply = resolver.resolve(DNSRecord.question(qhost, "A"))
        assert len(reply.rr) == 1
        assert reply.rr[0].rtype == QTYPE.CNAME
        assert str(reply.rr[0].rdata) == expected_target


def test_app_controller_tracks_foreground_app_sessions():
    ctrl = AppController()
    mono = [100.0]
    fg = ["chrome.exe"]

    e1 = ctrl.track_foreground_app(foreground_fn=lambda: fg[0], monotonic_fn=lambda: mono[0])
    assert len(e1) == 1
    assert e1[0].event_type == "app_start" and e1[0].app_name == "chrome.exe"

    # Switch to code.exe after 45 seconds -> emits app_stop(45s) + app_start(code.exe)
    mono[0] += 45.0
    fg[0] = "code.exe"
    e2 = ctrl.track_foreground_app(foreground_fn=lambda: fg[0], monotonic_fn=lambda: mono[0])
    assert len(e2) == 2
    assert e2[0].event_type == "app_stop" and e2[0].app_name == "chrome.exe" and e2[0].duration_sec == 45
    assert e2[1].event_type == "app_start" and e2[1].app_name == "code.exe"

    # Flush active session after 20 seconds
    mono[0] += 20.0
    e3 = ctrl.flush_active_session(monotonic_fn=lambda: mono[0])
    assert len(e3) == 1
    assert e3[0].event_type == "app_stop" and e3[0].app_name == "code.exe" and e3[0].duration_sec == 20


def test_dns_proxy_allowlist_overrides_blocklist():
    resolver = OGKDNSResolver()
    resolver.update_policy(
        {
            "blocked_domains": ["example.com"],
            "allowed_domains": ["example.com"],
            "safesearch_enabled": False,
        }
    )
    # Mock upstream so test does not depend on external network
    resolver._forward_upstream = lambda req: req.reply()  # type: ignore[method-assign]
    reply = resolver.resolve(DNSRecord.question("sub.example.com", "A"))
    assert reply.header.rcode == RCODE.NOERROR


def test_agent_dry_run_mode_uses_simulated_overlay_instead_of_lock_workstation(tmp_path: Path, monkeypatch):
    from agent.src.config import AgentConfig
    import agent.src.service.agent_core as agent_core_mod

    monkeypatch.setenv("OGK_AGENT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KIDGATE_DRY_RUN", "true")
    cfg = AgentConfig.from_env()
    assert cfg.dry_run is True

    real_lock_calls = []
    overlay_calls = []
    monkeypatch.setattr(agent_core_mod, "lock_windows_workstation", lambda: real_lock_calls.append(1))
    monkeypatch.setattr(
        agent_core_mod,
        "show_dry_run_lock_overlay",
        lambda reason, on_dismiss=None: (overlay_calls.append(reason), on_dismiss() if on_dismiss else None),
    )

    core_dry = agent_core_mod.AgentCore(cfg, enable_dns=False, enable_tray_watchdog=False)
    core_dry._trigger_workstation_lock("Locked remotely by parent.", force_overlay=True)
    # Wait briefly for background overlay thread
    import time as _time
    _time.sleep(0.1)
    assert len(real_lock_calls) == 0
    assert overlay_calls == ["Locked remotely by parent."]

    # Default production behavior (dry_run=False) MUST call real lock_windows_workstation()
    monkeypatch.delenv("KIDGATE_DRY_RUN", raising=False)
    cfg_prod = AgentConfig.from_env()
    assert cfg_prod.dry_run is False
    core_prod = agent_core_mod.AgentCore(cfg_prod, enable_dns=False, enable_tray_watchdog=False)
    core_prod._trigger_workstation_lock("Locked remotely by parent.")
    assert len(real_lock_calls) == 1
