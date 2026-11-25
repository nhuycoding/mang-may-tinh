"""Integration tests covering OGK-Server APIs, Auth/CSRF/RBAC/Anti-IDOR, Enrollment, Policy HMAC,
Heartbeat, WebSocket Urgent Commands, Offline Sync, Retention, and Dashboard UI."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from server.app.crypto import verify_policy_signature
from server.app.database import SessionLocal
from server.app.main import app
from server.app.models import Event
from server.app.services.retention_service import purge_expired_events


def _login(client: TestClient, email: str, password: str) -> dict[str, str]:
    resp = client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return {"X-CSRF-Token": resp.json()["csrf_token"]}


def _enroll_test_device(client: TestClient, headers: dict[str, str], child_id: int, name: str = "Win11-Lab"):
    pc = client.post("/enroll/pairing-code", json={"child_id": child_id}, headers=headers)
    assert pc.status_code == 201
    code = pc.json()["pairing_code"]
    assert len(code) == 8

    enr = client.post(
        "/enroll",
        json={
            "pairing_code": code,
            "device_fingerprint": f"FP-{name}-{code}",
            "device_name": name,
            "os_version": "Windows 11 x64",
            "agent_version": "1.0.0",
        },
    )
    assert enr.status_code == 201, enr.text
    return enr.json()


def test_auth_login_lockout_after_5_failed_attempts_and_session_logout(client: TestClient):
    # Register a fresh parent so lockout does not affect demo accounts
    reg = client.post(
        "/auth/register",
        json={
            "email": "lockout_test@ogk.local",
            "display_name": "Lockout Parent",
            "password": "ValidPassword123!",
        },
    )
    assert reg.status_code == 201

    for _ in range(5):
        r = client.post("/auth/login", json={"email": "lockout_test@ogk.local", "password": "WrongPassword!"})
        assert r.status_code == 401

    # 6th attempt -> 423 Locked even with correct password
    locked = client.post(
        "/auth/login",
        json={"email": "lockout_test@ogk.local", "password": "ValidPassword123!"},
    )
    assert locked.status_code == 423

    # Verify demo parent login + server-side session invalidation on logout
    headers = _login(client, "parent@ogk.local", "ParentPass123!")
    assert client.get("/auth/me").status_code == 200
    out = client.post("/auth/logout", headers=headers)
    assert out.status_code == 200
    assert client.get("/auth/me").status_code == 401


def test_csrf_protection_blocks_state_changing_without_token(client: TestClient):
    _login(client, "parent@ogk.local", "ParentPass123!")
    children = client.get("/auth/children").json()
    cid = children[0]["id"]

    # Missing X-CSRF-Token must fail with 403 Forbidden
    resp = client.post("/enroll/pairing-code", json={"child_id": cid})
    assert resp.status_code == 403


def test_enrollment_pairing_code_token_refresh_and_revocation(client: TestClient):
    headers = _login(client, "parent@ogk.local", "ParentPass123!")
    cid = client.get("/auth/children").json()[0]["id"]
    enrolled = _enroll_test_device(client, headers, cid, name="Revoke-Test-PC")

    # Refresh access token
    ref = client.post("/enroll/refresh", json={"refresh_token": enrolled["refresh_token"]})
    assert ref.status_code == 200
    new_access = ref.json()["access_token"]
    assert client.get("/policy", headers={"Authorization": f"Bearer {new_access}"}).status_code == 200

    # Revoke device -> all tokens invalidated immediately
    rev = client.delete(f"/enroll/devices/{enrolled['device_id']}", headers=headers)
    assert rev.status_code == 200
    assert client.get("/policy", headers={"Authorization": f"Bearer {new_access}"}).status_code == 401
    assert client.post("/enroll/refresh", json={"refresh_token": enrolled["refresh_token"]}).status_code == 401


def test_policy_hmac_signed_delivery_and_audit_log_visibility(client: TestClient):
    headers = _login(client, "parent@ogk.local", "ParentPass123!")
    cid = client.get("/auth/children").json()[0]["id"]
    enrolled = _enroll_test_device(client, headers, cid, name="Policy-PC")

    # Update policy
    upd = client.put(
        f"/policy/{cid}",
        json={"weekday_quota_sec": 5400, "blocked_domains": ["blocked-test-01.example"]},
        headers=headers,
    )
    assert upd.status_code == 200
    new_ver = upd.json()["policy_version"]

    # Agent fetches policy and verifies per-device HMAC-SHA256 signature
    pol = client.get("/policy", headers={"Authorization": f"Bearer {enrolled['access_token']}"}).json()
    assert pol["policy_version"] == new_ver
    assert verify_policy_signature(pol["payload_json"], pol["signature_hmac"], enrolled["hmac_secret"]) is True

    # Audit log records the change and is visible to Agent Tray UI
    audit_agent = client.get(
        "/audit/agent", headers={"Authorization": f"Bearer {enrolled['access_token']}"}
    ).json()
    assert any(item["action"] == "policy.update" for item in audit_agent["items"])


def test_offline_event_batch_sync_idempotency_and_url_sanitization(client: TestClient):
    headers = _login(client, "parent@ogk.local", "ParentPass123!")
    cid = client.get("/auth/children").json()[0]["id"]
    enrolled = _enroll_test_device(client, headers, cid, name="Offline-PC")
    dev_h = {"Authorization": f"Bearer {enrolled['access_token']}"}

    now = datetime.now(timezone.utc).isoformat()
    batch = {
        "events": [
            {
                "idempotency_key": "offline-sync-key-0001",
                "ts": now,
                "type": "domain_query",
                "subject": "https://en.wikipedia.org/wiki/Python_(programming_language)",
                "duration_sec": 0,
            },
            {
                "idempotency_key": "offline-sync-key-0001",  # duplicate!
                "ts": now,
                "type": "domain_query",
                "subject": "https://en.wikipedia.org/wiki/Python_(programming_language)",
                "duration_sec": 0,
            },
        ]
    }
    r1 = client.post("/events/batch", json=batch, headers=dev_h).json()
    assert r1["accepted"] == 1 and r1["duplicates_skipped"] == 1

    # Re-sending the same batch must skip all as duplicates
    r2 = client.post("/events/batch", json=batch, headers=dev_h).json()
    assert r2["accepted"] == 0 and r2["duplicates_skipped"] == 2

    evs = client.get(f"/events?child_id={cid}").json()["items"]
    assert any(e["subject"] == "wikipedia.org" for e in evs)
    assert all("http" not in e["subject"] and "/" not in e["subject"] for e in evs)


def test_heartbeat_clock_tamper_detection_and_realtime_websocket_commands(client: TestClient):
    headers = _login(client, "parent@ogk.local", "ParentPass123!")
    cid = client.get("/auth/children").json()[0]["id"]
    enrolled = _enroll_test_device(client, headers, cid, name="WS-PC")
    dev_id = enrolled["device_id"]
    dev_h = {"Authorization": f"Bearer {enrolled['access_token']}"}

    # Heartbeat with 3-hour rolled-back client_time
    hb = client.post(
        "/events/heartbeat",
        json={
            "status": "online",
            "used_quota_sec_today": 120,
            "current_policy_version": 0,
            "client_time": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(),
            "clock_tamper_detected": False,
        },
        headers=dev_h,
    ).json()
    assert hb["policy_update_required"] is True
    assert abs(hb["clock_skew_sec"]) > 10000

    # WebSocket receives urgent command immediately
    with client.websocket_connect(f"/commands/ws/{dev_id}?token={enrolled['access_token']}") as ws:
        resp = client.post("/commands", json={"device_id": dev_id, "command_type": "add_15_mins"}, headers=headers)
        assert resp.status_code == 201
        msg = ws.receive_json()
        assert msg["type"] == "command"
        assert msg["command_type"] == "add_15_mins"
        ws.send_json({"type": "ack", "command_id": msg["command_id"], "status": "acknowledged"})


def test_policy_update_pushes_realtime_websocket_event(client: TestClient):
    headers = _login(client, "parent@ogk.local", "ParentPass123!")
    cid = client.get("/auth/children").json()[0]["id"]
    enrolled = _enroll_test_device(client, headers, cid, name="WS-Policy-PC")
    dev_id = enrolled["device_id"]

    with client.websocket_connect(f"/commands/ws/{dev_id}?token={enrolled['access_token']}") as ws:
        upd = client.put(
            f"/policy/{cid}",
            json={"weekday_quota_sec": 4500, "blocked_domains": ["realtime-block.test"]},
            headers=headers,
        )
        assert upd.status_code == 200
        new_ver = upd.json()["policy_version"]

        msg = ws.receive_json()
        assert msg["type"] == "policy_updated"
        assert msg["policy_version"] == new_ver
        assert msg["child_id"] == cid


def test_rbac_anti_idor_and_child_transparency_dashboard(client: TestClient):
    headers = _login(client, "parent@ogk.local", "ParentPass123!")
    cid = client.get("/auth/children").json()[0]["id"]
    _enroll_test_device(client, headers, cid, name="RBAC-Child-PC")

    # Strict UI & API isolation for Parent: CANNOT access /child or /reports/today/{cid}, and no /child link in navbar
    parent_dash = client.get("/dashboard")
    assert parent_dash.status_code == 200
    assert 'href="/child"' not in parent_dash.text
    assert client.get("/child").status_code == 403
    assert client.get(f"/reports/today/{cid}").status_code == 403

    # Second parent cannot access parent1's child policy, reports, or events (Anti-IDOR -> 404)
    with TestClient(app) as c_parent2:
        _login(c_parent2, "parent2@ogk.local", "Parent2Pass123!")
        assert c_parent2.get(f"/policy/{cid}").status_code == 404
        assert c_parent2.get(f"/reports/summary/{cid}").status_code == 404
        assert c_parent2.get(f"/events?child_id={cid}").status_code == 404

    # Child-view cannot access parent/admin routes (API -> 403, /dashboard -> redirect to /child)
    with TestClient(app) as c_child:
        ch_headers = _login(c_child, "child@ogk.local", "ChildPass123!")
        assert c_child.put(f"/policy/{cid}", json={"weekday_quota_sec": 9999}, headers=ch_headers).status_code == 403
        assert c_child.get(f"/policy/{cid}").status_code == 403
        assert c_child.get(f"/reports/summary/{cid}").status_code == 403
        assert c_child.get("/events").status_code == 403
        assert c_child.get("/commands").status_code == 403
        assert c_child.get("/enroll/devices").status_code == 403
        assert c_child.get(f"/dashboard/partials/extensions?child_id={cid}").status_code == 403

        dash_redir = c_child.get("/dashboard", follow_redirects=False)
        assert dash_redir.status_code == 302
        assert dash_redir.headers["location"] == "/child"

        # Child-view CAN access /child, /reports/today/{cid}, /audit, and submit extension request
        assert c_child.get("/audit").status_code == 200
        today_api = c_child.get(f"/reports/today/{cid}")
        assert today_api.status_code == 200
        assert "remaining_seconds" in today_api.json()

        ext_req = c_child.post(
            f"/events/child/extension-request?child_id={cid}",
            json={"requested_minutes": 15, "reason": "Finishing homework"},
            headers=ch_headers,
        )
        assert ext_req.status_code == 201

        page = c_child.get("/child")
        assert page.status_code == 200
        assert "What I used today" in page.text
        assert 'href="/dashboard"' not in page.text

    # Admin CAN access BOTH Parent Dashboard and Child View
    with TestClient(app) as c_admin:
        _login(c_admin, "admin@ogk.local", "AdminPass123!")
        adm_dash = c_admin.get("/dashboard")
        assert adm_dash.status_code == 200
        assert 'href="/child"' in adm_dash.text
        adm_child = c_admin.get(f"/child?child_id={cid}")
        assert adm_child.status_code == 200
        assert 'href="/dashboard"' in adm_child.text


def test_data_retention_90_days_and_delete_all_child_data_wipe(client: TestClient):
    headers = _login(client, "parent@ogk.local", "ParentPass123!")
    cid = client.get("/auth/children").json()[0]["id"]
    enrolled = _enroll_test_device(client, headers, cid, name="Wipe-PC")

    # Insert an event 120 days old and verify 90-day retention job purges it
    old_ts = datetime.now(timezone.utc) - timedelta(days=120)
    with SessionLocal() as db:
        db.add(
            Event(
                idempotency_key="old-retention-event-120d",
                ts=old_ts,
                device_id=enrolled["device_id"],
                child_id=cid,
                type="domain_query",
                subject="example.com",
                duration_sec=0,
            )
        )
        db.commit()
        purged = purge_expired_events(db, retention_days=90)
        assert purged >= 1

    # "Delete all my child's data" wipes server events and queues `wipe_local_data` command
    wipe = client.delete(f"/auth/children/{cid}/data", headers=headers)
    assert wipe.status_code == 200
    body = wipe.json()
    assert body["status"] == "wiped"
    assert body["devices_queued"] >= 1
    assert client.get(f"/events?child_id={cid}").json()["total"] == 0
