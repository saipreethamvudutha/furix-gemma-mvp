@echo off
REM Furix Gemma MVP - Windows launcher. Run from the project folder.
cd /d "%~dp0"

if not exist .venv (
    python -m venv .venv
    .venv\Scripts\python -m pip install --upgrade pip
    .venv\Scripts\pip install -r requirements.txt
)
if not exist .env copy .env.example .env

.venv\Scripts\uvicorn furix_mvp.api:app --host 0.0.0.0 --port 8080
