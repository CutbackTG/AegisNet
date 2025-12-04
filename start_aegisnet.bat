@echo off
echo ================================
echo   Starting AegisNet Server
echo ================================

REM Navigate to project folder
cd /d C:\Users\TJWor\Documents\Major

REM Activate GPU virtual environment
call .venv-gpu\Scripts\activate.bat

echo [OK] Virtual environment activated
echo Starting Uvicorn server...

REM Start API & Dashboard
start "" http://127.0.0.1:8000
uvicorn inference_service:app --reload --port 8000
