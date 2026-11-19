# OGK Privacy Policy & Data Mapping

> **Core Philosophy:** *"A companion tool, not stealth spyware."*

OGK is engineered around **data minimization**, **encryption at rest**, and **bidirectional transparency**: both parents and children can see what is recorded and every rule change made to the system.

---

## 1. Data-Mapping Table

| Data Category | Exact Fields Stored | Storage Location | Protection at Rest | Retention | Who Can View |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Account Credentials** | `email`, `display_name`, `role`, `password_hash` | Server SQLite (WAL) — `users` | `Argon2id` password hash (min 10 chars) | Until account deletion | Account owner, `admin` |
| **Web Sessions** | `id` (SHA-256 of cookie), `csrf_token`, `ip_address`, `expires_at` | Server SQLite (WAL) — `web_sessions` | Raw cookie token never stored (SHA-256 hashed); `HttpOnly`, `Secure`, `SameSite=Lax` | 12-hour TTL (revoked immediately on logout) | Server internal |
| **Child Profile** | `name_encrypted`, `age_group`, `timezone` | Server SQLite (WAL) — `children` | `AES-256-GCM` encrypted name (`OGK_MASTER_KEY` from env) | Until parent deletes child | Owning `parent`, linked `child-view`, `admin` |
| **Device Identity & Tokens** | `device_id`, `device_fingerprint_hash`, `hmac_secret_encrypted`, `token_hash` | Server `devices`/`device_tokens`; Agent `C:\ProgramData\OGK-Agent\ogk_agent.db` | Server: SHA-256 hashed tokens + AES-256-GCM HMAC secret; Agent: Windows **DPAPI** (`LocalMachine`) + Windows ACLs (`SYSTEM`/`Administrators` write-only) | Until device revoked | Owning `parent`, `admin` |
| **Activity Events (Strict F3 Schema)** | `ts`, `device_id`, `child_id`, `type`, `subject`, `duration_sec`, `policy_id` (+ `idempotency_key`) | Server `events`; Agent `offline_events` | Subject strictly sanitized to **app name** or **second-level domain** (e.g., `youtube.com`) | **90 days** automated background purge, or instant delete via **"Delete All My Child's Data"** | Owning `parent`, linked `child-view`, `admin` |
| **Audit Log (F4)** | `actor_email`, `actor_role`, `timestamp`, `source_ip`, `action`, `old_value`, `new_value` | Server `audit_logs`; Agent `audit_log_cache` (read-only) | Append-only record of every config change | Retained for family accountability | Owning `parent`, linked `child-view`, Agent Tray UI, `admin` |
| **Domain Categories** | `domain`, `category` (6 safe categories) | Server `domain_categories`; Agent cached policy | Public/simulated safe test domains only (zero real adult/NSFW domains) | Static seed + parent custom rules | Authenticated users |

### What OGK NEVER Collects
- **No full URLs, query strings, or page titles** (e.g. `https://youtube.com/watch?v=...` is reduced to `youtube.com`).
- **No screenshots, webcam/microphone feeds, or keystrokes**.
- **No chat messages, emails, or file contents**.
- **No stealth operation**: if the visible Tray UI icon cannot be displayed or becomes unresponsive, the OGK-Agent Service **self-terminates** and logs the event.

---

## 2. Offline Mode & Policy Expiration Policy
When the Windows computer has no internet connection:
- OGK-Agent continues enforcing the last HMAC-verified cached policy, counting screen time via `time.monotonic()`, and buffering events in `offline_events` with a unique `idempotency_key`.
- When connectivity returns, events are batch-synced without duplicate counting.
- **Explicit Expiration Behavior (`offline_expiry_days`, default `3` days):**
  - `fail_closed` (default): After `N` days without a verified `server_time` heartbeat, the workstation locks until connectivity is restored.
  - `fail_open` (configurable by parent): After `N` days offline, time/schedule blocking pauses until connectivity is restored.

---

## 3. Right to Instant Erasure
Parents can click **"Delete All My Child's Data"** on the Parent Dashboard (`DELETE /auth/children/{child_id}/data`). This simultaneously:
1. Deletes all `events` and `time_extension_requests` for that child on the Server.
2. Pushes the urgent `wipe_local_data` command over WebSocket (and Heartbeat fallback) so every enrolled Windows Agent erases its local `offline_events`, `daily_usage`, and `audit_log_cache` tables.
3. Records an entry in the Audit Log so the action is transparent.

---

## 4. Child-Friendly Privacy Guide ("What OGK Knows About Me")

Hi there! Here is a simple, honest guide to how **OGK** works on your computer:

- **I am always visible:** Look at the bottom-right corner of your screen (the system tray). You will always see my icon there. I am **never** allowed to hide from you!
- **What I count:** I count how many minutes you use the computer each day and which apps or main websites (like `wikipedia.org` or `youtube.com`) you open.
- **What I do NOT look at:** I **never** take screenshots, I **never** read your messages, I **never** record what you type, and I **never** save the exact pages or videos you visit.
- **When something is blocked:** I will always pop up a clear message explaining *why* an app or website was paused, and you can click **"Request more time"** whenever you need extra minutes for homework or projects.
- **You can check everything:** Open **"What I used today"** from the tray icon or sign in to the **Child View** page anytime to see your own activity and every change your parent makes to the rules.
