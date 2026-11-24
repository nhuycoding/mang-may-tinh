# ROLE & OBJECTIVE
You are a Senior Systems & Backend Engineer specializing in Windows Internals (Python) and Web Security (FastAPI). Your task is to build a complete **OGK (Child Computer Usage Management Application)** following the philosophy: *"A companion tool, not stealth spyware."*

The system must run natively on Windows 10/11 (x64) and fulfill all MANDATORY functional, networking, and security requirements specified below.

---

# 1. TECH STACK & DIRECTORY STRUCTURE
- **Language & Frameworks:** Python 3.11+, FastAPI, Uvicorn, SQLAlchemy, SQLite (with WAL mode enabled), `pywin32`, `psutil`, `cryptography`, `passlib[argon2]`, `dnslib` (or `dnspython`), `pystray` + `tkinter`/`PySide6` (for Tray UI).
- **Dashboard:** Jinja2 + HTMX + TailwindCSS (via CDN) or lightweight React. Must be mobile-responsive and usable on mobile browsers.
- **Required Directory Structure:**
  - `/agent`: Windows Service + Tray UI source code, `requirements.txt`, install/uninstall scripts for a clean Windows machine.
  - `/server`: FastAPI source code, Alembic/migrations, script to generate a Self-signed CA & TLS certificate for lab environments, seed script (>= 200 categorized safe domains + demo accounts).
  - `/dashboard`: Parent web dashboard and child transparency screen.
  - `/tests`: Automated tests using `pytest` (minimum 15 unit tests and 5 integration tests).
  - `/docs`: `PRIVACY.md` (data-mapping table + a child-friendly version), `THREATMODEL.md` (STRIDE table with >= 8 threats).
  - `/README.md`: Step-by-step setup guide to deploy on a clean Windows machine within 15 minutes, including demo credentials.

---

# 2. SYSTEM ARCHITECTURE & PROTOCOLS

## A. OGK-Server (`/server`) & Dashboard (`/dashboard`)
1. **Data Model:** Support `1 parent : n children : m devices`. Use SQLite with WAL mode.
2. **Core API Endpoints:** `/auth`, `/enroll`, `/policy`, `/events`, `/commands`, `/reports`, `/audit` (with pagination and IP-based rate limiting).
3. **Lifecycle & Protocols:**
   - **Enrollment:** Parent generates an 8-character pairing code (10-minute TTL) on the dashboard. Agent sends the code + `device_fingerprint` -> Server returns `device_id`, short-lived `access_token` (15-min TTL), and long-lived `refresh_token`.
   - **Heartbeat (60s):** Agent sends status, used quota, and current `policy_version`; Server responds with `server_time`, latest `policy_version`, and pending commands. If `policy_version` mismatches, Agent fetches `GET /policy`.
   - **WebSocket (Urgent Commands < 5s latency):** Push real-time commands from Server to Agent: `lock_now`, `unlock`, `add_15_mins`, `wipe_local_data`.
   - **Policy Integrity:** Every policy issued by the Server must be versioned (`policy_version`) and signed with `HMAC-SHA256`. Agent must verify the signature before applying and reject tampered policies.

## B. OGK-Agent (`/agent` — Windows 10/11 x64)
Split into two components communicating via Named Pipe or `127.0.0.1` HTTP with a local auth token:
1. **Windows Service (running as `LocalSystem`):**
   - Built with `pywin32` (`win32serviceutil`), configured with SCM Service Recovery Options to auto-restart on failure.
   - **Local Storage:** SQLite database stored in `C:\ProgramData\OGK-Agent\` with a setup script configuring Windows ACLs so only `SYSTEM` and `Administrators` have write permissions. Stores the latest cached policy and an offline event queue.
   - **Offline Mode:** Enforce cached policy, continue screen-time counting, and buffer events locally. When connectivity returns, batch-sync events using an `idempotency_key` to prevent duplicate counting. Explicitly implement and document the policy expiration behavior (fail-open or fail-closed after N days offline).
2. **Tray UI (running in User Session):**
   - System tray icon, remaining time display, **"Request more time"** button, and clear blocking reason popups.
   - Transparency screen: **"What I used today"** (simple, child-friendly language) and read-only access to the **Audit Log** of parent configuration changes.
   - **Anti-Abuse Rule (MANDATORY):** No stealth mode. If the Service detects that the Tray UI cannot display its icon or is unresponsive beyond a threshold, the Agent must self-terminate and log the event.

---

# 3. MANDATORY FUNCTIONAL SPECIFICATIONS (F1 – F5)

## F1. Screen-Time Management
- **Daily Quota:** Separate limits for weekdays and weekends (e.g., setting a 3-minute quota must lock the session on time).
- **Weekly Schedule (7×48 Matrix):** Allow/block schedule with 30-minute resolution. Outside allowed hours, lock the workstation (`LockWorkStation`) within 5 seconds.
- **Active Usage Tracking:** Pause counting when the screen is locked or user is idle (`GetLastInputInfo`) for > 5 minutes. Accuracy must be within ±30 seconds per hour.
- **Warnings & Grace Period:** Notify via Tray UI at 10, 5, and 1 minute remaining; provide a 60-second grace period for the child to save their work before locking.
- **Anti-Clock Tampering:** Use `time.monotonic()` for local elapsed time tracking combined with `server_time` cross-checking on every heartbeat. Rolling back the system clock (e.g., by 3 hours) must not restore quota and must trigger a tamper event log.

## F2. Application & Website Filtering
- **Application Control:** Allow/block list matching **process name AND executable SHA-256 hash** (renaming `notepad.exe` to `game.exe` must still be accurately detected). On block: terminate the process via `psutil` and trigger a Tray UI popup explaining the reason (never fail silently).
- **Website Filtering via Local DNS Proxy (`127.0.0.1:53`):**
  - Block exact domains and all subdomains (return `NXDOMAIN` or `0.0.0.0`).
  - **SafeSearch Enforcement:** Map search engine domains (Google, Bing, DuckDuckGo) to their respective SafeSearch DNS records (e.g., `forcesafesearch.google.com`).
  - **6-Category Classification:** `education`, `entertainment`, `social_media`, `games`, `inappropriate`, `uncategorized` with a default policy for ages 6–11.
  - **Seed Dataset (>= 200 domains):** Provide a safe test dataset. **STRICTLY PROHIBITED** from including any real adult/NSFW domains in code or database; use neutral simulated domains only (e.g., `blocked-test-1.example`, `adult-sim.test`).

## F3. Transparent Activity Logging & Reporting
- **Strict Event Schema:** Only store these fields: `ts, device_id, child_id, type, subject, duration_sec, policy_id`.
  - `type` must be in: `{app_start, app_stop, domain_query, blocked_app, blocked_domain, quota_warning, locked, unlock_request, override_granted}`.
  - `subject` must only store the app name or **second-level domain** (e.g., `youtube.com`), NEVER full URLs.
- **Parent Dashboard:** Daily/weekly usage charts, Top 10 apps, Top 10 domains, block counts, and child time-extension request queue (approve/deny).
- **Data Retention:** Automated background job deleting data older than 90 days. A **"Delete all my child's data"** button that wipes data simultaneously on the Server and triggers a local cache wipe on the Agent.

## F4. Remote Management & Audit Log
- **Audit Log:** Record every configuration change: `actor`, `timestamp`, `source IP`, `old_value`, `new_value`. Accessible to both parents and the child.

## F5. Security & Privacy
- **Parent Auth:** Password hashing with `Argon2id` (min 10 chars), 15-minute lockout after 5 failed attempts, IP rate limiting.
- **Web Sessions:** `HttpOnly`, `Secure`, `SameSite=Lax` cookies; 12-hour TTL; server-side session invalidation on logout; CSRF protection on all state-changing requests.
- **Transport Security:** TLS 1.2+ (with lab Self-signed CA script). Agent must implement **Certificate Pinning** (verify server cert fingerprint) and refuse mismatched connections.
- **Data at Rest:** Encrypt sensitive fields using `AES-GCM` (key loaded from env vars or Windows DPAPI, never hardcoded). Hash device tokens/secrets in DB and maintain a token revocation list when removing devices.
- **RBAC & Anti-IDOR:** Three roles: `parent`, `child-view`, `admin`. Enforce ownership checks at the SQLAlchemy query layer to prevent IDOR.

---

# 4. EXECUTION WORKFLOW
Build this project step-by-step without skipping any files:
1. **Step 1:** Set up the directory structure, database schemas (Server & Agent), and the Self-signed TLS certificate generation script.
2. **Step 2:** Implement `/server` completely (FastAPI, Auth, RBAC, Enrollment, Policy HMAC, Heartbeat, WebSocket, Reports, Audit Log, Seed script with >= 200 safe domains).
3. **Step 3:** Implement `/dashboard` completely (Mobile-responsive Parent Dashboard + Child Transparency Screen).
4. **Step 4:** Implement `/agent` completely (Windows Service, Anti-tamper Screen-time Counter, SHA-256 App Controller, Local DNS Proxy `127.0.0.1:53` + SafeSearch, Local SQLite Cache + Offline Sync, Tray UI).
5. **Step 5:** Write `/tests` (>= 15 unit tests + 5 integration tests) and documentation (`/docs/PRIVACY.md`, `/docs/THREATMODEL.md`, `/README.md`).

Start with **Step 1** now and wait for my confirmation before proceeding to Step 2.