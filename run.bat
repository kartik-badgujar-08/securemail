@echo off
setlocal
cd /d "%~dp0"

REM Check if bash is available (e.g. Git Bash, MSYS2, WSL)
where bash >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    bash "%~dp0run.sh" %*
    goto :eof
)

REM Fallback if bash is not found in PATH:
echo [!] Bash was not detected in PATH. Running Windows fallback...

REM Check/copy backend .env
if not exist "backend\.env" (
    if exist "backend\.env.example" (
        echo [*] Initializing backend\.env from template...
        copy "backend\.env.example" "backend\.env" >nul
    )
)

REM Check node_modules
if not exist "frontend\node_modules" (
    echo [*] Installing frontend dependencies...
    cd frontend && call npm.cmd install && cd ..
)

echo ========================================================================
echo       EMAIL SECURITY & TLS PROTOCOL ANALYSIS PLATFORM
echo ========================================================================
echo  Frontend Dashboard:   http://localhost:5173
echo  Backend API Server:   http://localhost:8000
echo  Interactive API Docs: http://localhost:8000/docs
echo ========================================================================
echo Starting Backend and Frontend services...
start "Email Security - Backend API" cmd /k "cd /d %~dp0backend && python run.py"
start "Email Security - Frontend UI" cmd /k "cd /d %~dp0frontend && npm.cmd run dev"

echo Waiting for services to initialize...
timeout /t 3 /nobreak >nul
echo Opening application in default browser...
start http://localhost:5173

echo Both services launched successfully.
echo You can close this launcher window at any time.
pause

