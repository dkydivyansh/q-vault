# Operations, Deployment & Console Guide (`src/app/`)

> Return to [`docs/architecture.md`](architecture.md) for system architecture and operational flows.

---

## 1. Prerequisites

* **Operating System:** Linux, macOS, or Windows
* **Python:** `3.11+` (verified on Python `3.12.10`)
* **Network Isolation:** All cryptographic primitives, SQLite WAL persistence, audit logging, and deterministic detection execute locally without external network or AI/ML service dependencies.

---

## 2. Environment Setup

### Step 1: Install Dependencies

```bash
git clone <repository-url>
cd q-vault

python3 -m venv .venv
source .venv/bin/activate   # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 2: Configure Runtime Secrets

Generate a 32-byte Master Key Encryption Key (KEK) for sealing authority keys, ledger checkpoint keys, and encrypted backups. Never commit `.env` files containing live keys:

```bash
cp config/.env.example .env
export QVAULT_MASTER_KEK=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

Windows PowerShell:

```powershell
Copy-Item config\.env.example .env
$env:QVAULT_MASTER_KEK = python3 -c "import secrets; print(secrets.token_hex(32))"
```

Policy settings (rotation grace window, clock-skew tolerance, anti-replay window size, allowed service-graph edges, and checkpoint interval) are loaded from `config/`.

---

## 3. Application Execution & CLI

The operator CLI inside `src/app/` exposes web hosting, status inspection, offline log verification, manual revocation, live terminal monitoring, and benchmark execution:

```bash
# Start the FastAPI Control Plane, Protected Service Nodes & Web Console (http://127.0.0.1:8700/)
python3 -m src.app.console serve --host 127.0.0.1 --port 8700

# Execute the live end-to-end operational walkthrough across SDK components
python3 -m src.app.console demo

# Run the reproducible performance, revocation-latency & 1,050-event detection benchmark
python3 -m src.app.console benchmark

# Inspect registered service nodes, active key epoch, and audit chain head
python3 -m src.app.console status --db-path ./data/authority.db --ledger-path ./data/audit.jsonl

# Launch the live terminal dashboard
python3 -m src.app.console watch --db-path ./data/authority.db --ledger-path ./data/audit.jsonl

# Verify SHA-256 hash-chain integrity offline
python3 -m src.app.console verify-log --ledger-path ./data/audit.jsonl

# Execute manual emergency key revocation for a compromised node
python3 -m src.app.console revoke NodeA --db-path ./data/authority.db --reason "credential compromise"
```

---

## 4. HTTP Control Plane & Service Endpoints

When running `serve`, the FastAPI application exposes:

* **Web Console UI (`GET /`):** Live dashboard for viewing registered nodes, active key epoch, authorized service-graph edges, watchdog alerts, and recent audit entries, plus controls for epoch rotation, encrypted service transfers, chain verification, backups, and revocation.
* **Control Plane & Telemetry API (`/api/v1/*`):** Status snapshots, node registration, epoch rotation, node revocation, backup/restore, ledger verification, detector ingestion/flush, metrics reporting, and lateral-movement verification scenarios.
* **Protected Service Node Endpoints (`/nodes/<NodeID>/pqc/*`):** Per-service gateway endpoints handling `/pqc/handshake`, `/pqc/receive`, `/pqc/ticket`, `/pqc/resume`, and `/pqc/revocation`.
