# ULPF Nexus v4.0.3 — FINAL Windows Build

ULPF Nexus is an air-gapped, lossless universal log preprocessing and security investigation prototype.

## Windows quick start

1. Extract this ZIP.
2. Open the **project root** in VS Code — the folder containing `backend`, `frontend`, and these scripts.
3. Open a PowerShell terminal at the project root.
4. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\START-WINDOWS.ps1
```

The script creates/uses `backend\.venv`, installs the compatible dependencies for Python 3.14, and starts FastAPI.

Open:

- http://127.0.0.1:8000
- http://127.0.0.1:8000/api/health

## Tests

Open a second PowerShell at the project root and run:

```powershell
.\RUN-TESTS-WINDOWS.ps1
```

**Do not run pytest from `backend`**. The tests live in the project-root `tests` directory.

## Manual start

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Presentation flow

SIH Demo Command Center → RUN COMPLETE DEMO

Then demonstrate:

Unknown Log → Log DNA → AI Mapping → Parser Evolution → Normalization → Lossless Proof → Detection → Correlation → Attack Path → Risk → Response → Forensics.

## Air-gapped model

The application does not require cloud AI. The GPT-OSS adapter can point at a locally hosted OpenAI-compatible `/v1/chat/completions` endpoint when enabled.

## Important

This package starts with a clean local SQLite database. Runtime data is created under `backend/data/`.
