# KidGate

Windows 10/11 (x64) screen-time management, application control, and local DNS filtering system built with **Python 3.11+**, **FastAPI**, **SQLite (WAL)**, **Jinja2 + HTMX + TailwindCSS**, **`pywin32`**, **`psutil`**, and **`dnslib`**.

---

## Repository Structure

```text
├── server/                 # FastAPI backend, Alembic migrations (SQLite WAL), Lab TLS CA generator, Seed script
├── dashboard/              # Mobile-responsive KidGate Dashboard & Child Activity View (Jinja2 + HTMX + Tailwind)
├── agent/                  # Windows Service (LocalSystem), Screen-Time Counter, SHA-256 App Control, DNS Proxy, Tray UI
├── tests/                  # Automated pytest suite (18 unit tests + 8 integration tests)
├── docs/                   # PRIVACY.md (data-mapping + child summary) & THREATMODEL.md (STRIDE 10 threats)
├── .env.example            # Environment variable template
└── README.md               # Clean Windows 10/11 setup guide
```

---

## Clean Windows 10/11 (x64) Setup Guide (< 15 Minutes)

### Prerequisites
- Windows 10/11 (x64) with Administrator PowerShell.
- **Python 3.11+** installed from [python.org](https://www.python.org/downloads/) (with *"Add Python to PATH"* enabled).

### Step 1 — Create Virtual Environment & Install Dependencies (3 min)
Open PowerShell in the project root:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r server\requirements.txt -r agent\requirements.txt
```

### Step 2 — Configure Environment Secrets (1 min)
Copy `.env.example` to `.env` and generate random keys:
```powershell
Copy-Item .env.example .env
python -c "import os, base64, secrets; print('OGK_MASTER_KEY=' + base64.urlsafe_b64encode(os.urandom(32)).decode()); print('OGK_POLICY_HMAC_FALLBACK_KEY=' + secrets.token_hex(32))"
```
Paste the two generated lines into `.env` (replacing the `REPLACE_WITH_...` placeholders).

### Step 3 — Generate Lab Self-Signed CA & TLS 1.2+ Certificates (1 min)
```powershell
python -m server.scripts.generate_certs
# Optional for LAN deployment:
# python -m server.scripts.generate_certs --ip 192.168.1.50 --dns ogk.lan
```
This creates `server/certs/ca.crt`, `server/certs/server.crt`, `server/certs/server.key`, and `server/certs/fingerprint.json`.
Copy the printed **`server_cert_sha256`** value for Agent Certificate Pinning in Step 6.

### Step 4 — Initialize Database (SQLite WAL) & Seed Demo Data (1 min)
```powershell
python -m server.scripts.init_db
python -m server.scripts.seed
```
Runs Alembic migrations (`journal_mode=wal`) and seeds **225 safe categorized domains** (6 categories; zero real adult/NSFW domains) plus demo accounts.

### Step 5 — Start KidGate Server (TLS 1.2+) (1 min)
```powershell
python -m server.app.main
```
Open **`https://127.0.0.1:8443/login`** in a desktop or mobile browser (accept the lab self-signed certificate or import `server/certs/ca.crt` into Trusted Root CAs).

#### Demo Credentials
| Role | Email | Password | Default Landing Page |
| :--- | :--- | :--- | :--- |
| **Parent** | `parent@ogk.local` | `ParentPass123!` | `/dashboard` (manages *"Be An"*) |
| **Child View** | `child@ogk.local` | `ChildPass123!` | `/child` (Daily Activity + Read-only Audit Log) |
| **Admin** | `admin@ogk.local` | `AdminPass123!` | `/dashboard` |
| **Parent 2 (IDOR test)** | `parent2@ogk.local` | `Parent2Pass123!` | `/dashboard` (isolated family) |

### Step 6 — Enroll & Install KidGate Agent on Windows (5 min)
1. Sign in as `parent@ogk.local` → **Devices & Commands** → click **Generate Pairing Code** (8 characters, valid 10 minutes).
2. In an **Administrator PowerShell**, enroll the machine with the pairing code and `server_cert_sha256`:
   ```powershell
   python -m agent.scripts.enroll --server https://127.0.0.1:8443 --code <8-CHAR-CODE> --pin <SERVER_CERT_SHA256>
   ```
3. Install the `OGKAgent` Windows Service (`LocalSystem`), configure `C:\ProgramData\OGK-Agent` ACLs, configure SCM auto-restart, and register the Tray UI:
   ```powershell
   .\agent\scripts\install_agent.ps1 -PythonExe "$PWD\.venv\Scripts\python.exe" -ConfigureLocalDNS
   ```
4. Launch the Tray UI for the current session (auto-starts on subsequent logins):
   ```powershell
   python -m agent.src.tray.tray_app
   ```

> **Console Debug Mode (without installing Windows Service):**
> ```powershell
> python -m agent.src.service.windows_service --console --no-dns --no-watchdog
> ```

### Step 7 — Uninstall Cleanly (Optional)
```powershell
.\agent\scripts\uninstall_agent.ps1 -PythonExe "$PWD\.venv\Scripts\python.exe" -PurgeData
```

---

## Running Automated Tests (`pytest`)
```powershell
.\.venv\Scripts\python.exe -m pytest -v tests/
```
Includes **18 unit tests** and **8 integration tests** (26 total).

---

## Documentation
- [Privacy Policy & Data Mapping](docs/PRIVACY.md)
- [STRIDE Threat Model (10 Threats)](docs/THREATMODEL.md)
