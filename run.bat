@echo off
rem Scam Shield launcher: LM Studio server + model + API on 0.0.0.0:8000. Everything stays on this laptop.
setlocal
cd /d "%~dp0"
if "%SCAMSHIELD_MODEL%"=="" set SCAMSHIELD_MODEL=qwen/qwen3-4b-2507
if "%SCAMSHIELD_GPU%"=="" set SCAMSHIELD_GPU=1.0
if "%SCAMSHIELD_CTX%"=="" set SCAMSHIELD_CTX=8192

echo [1/3] LM Studio server...
lms server start >nul 2>&1
echo [2/3] Loading model %SCAMSHIELD_MODEL% ...
lms ps | findstr /C:"%SCAMSHIELD_MODEL%" >nul
if errorlevel 1 (
  lms unload --all >nul 2>&1
  lms load %SCAMSHIELD_MODEL% --context-length %SCAMSHIELD_CTX% --parallel 1 --gpu %SCAMSHIELD_GPU% -y
  if errorlevel 1 echo WARNING: model did not load - app will run in rules-only mode.
)

echo [3/3] Starting API on http://localhost:8000 (phone: http://YOUR-LAPTOP-IP:8000)
start "" /min cmd /c "timeout /t 3 >nul & start http://localhost:8000"
".venv\Scripts\python.exe" -m uvicorn backend.server:app --host 0.0.0.0 --port 8000 --no-access-log
endlocal
