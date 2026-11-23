# KidGate Privacy Policy & Data Mapping

KidGate minimizes stored data, encrypts sensitive fields at rest, and provides both parents and children read-only visibility into recorded activity and configuration changes.

---

## 1. Data-Mapping Table

| Data Category | Exact Fields Stored | Storage Location | Protection at Rest | Retention | Who Can View |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Account Credentials** | `email`, `display_name`, `role`, `password_hash` | Server SQLite (WAL) — `users` | `Argon2id` password hash (min 10 chars) | Until account deletion | Account owner, `admin` |
| **Web Sessions** | `id` (SHA-256 of cookie), `csrf_token`, `ip_address`, `expires_at` | Server SQLite (WAL) — `web_sessions` | Raw cookie token never stored (SHA-256 hashed); `HttpOnly`, `Secure`, `SameSite=Lax` | 12-hour TTL (revoked immediately on logout) | Server internal |
| **Child Profile** | `name_encrypted`, `age_group`, `timezone` | Server SQLite (WAL) — `children` | `AES-256-GCM` encrypted name (`OGK_MASTER_KEY` from env) | Until parent deletes child | Owning `parent`, linked `child-view`, `admin` |
| **Device Identity & Tokens** | `device_id`, `device_fingerprint_hash`, `hmac_secret_encrypted`, `token_hash` | Server `devices`/`device_tokens`; Agent `C:\ProgramData\OGK-Agent\ogk_agent.db` | Server: SHA-256 hashed tokens + AES-256-GCM HMAC secret; Agent: Windows **DPAPI** (`LocalMachine`) + Windows ACLs (`SYSTEM`/`Administrators` write-only) | Until device revoked | Owning `parent`, `admin` |
| **Activity Events (Strict F3 Schema)** | `ts`, `device_id`, `child_id`, `type`, `subject`, `duration_sec`, `policy_id` (+ `idempotency_key`) | Server `events`; Agent `offline_events` | Subject sanitized to **app name** or **second-level domain** (e.g., `youtube.com`) | **90 days** automated background purge, or instant delete via **"Delete All My Child's Data"** | Owning `parent`, linked `child-view`, `admin` |
| **Audit Log (F4)** | `actor_email`, `actor_role`, `timestamp`, `source_ip`, `action`, `old_value`, `new_value` | Server `audit_logs`; Agent `audit_log_cache` (read-only) | Append-only record of configuration changes | Retained for audit history | Owning `parent`, linked `child-view`, KidGate Tray UI, `admin` |
| **Domain Categories** | `domain`, `category` (6 safe categories) | Server `domain_categories`; Agent cached policy | Public/simulated safe test domains only (zero real adult/NSFW domains) | Static seed + parent custom rules | Authenticated users |

### Data Not Collected
- Full URLs, query strings, or page titles (e.g., `https://youtube.com/watch?v=...` is reduced to `youtube.com`).
- Screenshots, webcam/microphone feeds, or keystrokes.
- Chat messages, emails, or file contents.
- Hidden/background-only operation: if the visible Tray UI icon cannot be displayed or stops responding, the KidGate Agent Service self-terminates and logs the event.

---

## 2. Offline Mode & Policy Expiration
When the Windows endpoint is offline:
- KidGate Agent enforces the last HMAC-verified cached policy, tracks screen time via `time.monotonic()`, and buffers events in `offline_events` with a unique `idempotency_key`.
- When connectivity returns, events are batch-synced without duplicate counting.
- **Policy Expiration (`offline_expiry_days`, default `3` days):**
  - `fail_closed` (default): After `N` days without a verified `server_time` heartbeat, the workstation locks until connectivity returns.
  - `fail_open` (configurable): After `N` days offline, time/schedule blocking pauses until connectivity returns.

---

## 3. Data Deletion
Parents can click **"Delete All My Child's Data"** on KidGate Dashboard (`DELETE /auth/children/{child_id}/data`). This action:
1. Deletes all `events` and `time_extension_requests` for that child on the Server.
2. Sends `wipe_local_data` over WebSocket (and Heartbeat fallback) so enrolled KidGate Agents erase local `offline_events`, `daily_usage`, and `audit_log_cache` tables.
3. Records an entry in the Audit Log.

---

## 4. Plain-Language Privacy Summary (For Children)

- **System tray icon:** KidGate stays visible in the bottom-right system tray and shows how much screen time is left today.
- **What is recorded:** Total minutes used per day, application names, main website names (like `wikipedia.org` or `youtube.com`), and blocked attempts.
- **What is not recorded:** No screenshots, no keystrokes, no messages, and no full page links.
- **Blocked items & extra time:** When an app or website is blocked, KidGate displays the reason. You can use **"Request more time"** to ask a parent for extra minutes.
- **Viewing your data:** Open **"What I used today & Audit Log"** from the tray icon or sign in to `/child` to see your daily activity and any rule changes made by a parent.
