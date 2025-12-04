@echo off
echo ============================
echo   Starting AegisNet Agent
echo ============================

cd /d C:\Users\TJWor\Documents\Major
call .venv-gpu\Scripts\activate.bat

echo [OK] Virtual environment activated
echo Running flow_agent.py...

python flow_agent.py
