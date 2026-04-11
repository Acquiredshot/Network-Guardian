@echo off
REM =============================================================
REM  Network Guardian — USB Auto-Setup (Windows)
REM  WOLFPAK INTERNAL USE ONLY — AUTHORIZED PERSONNEL ONLY
REM =============================================================

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "AGENT_DIR=%USERPROFILE%\.ng_agent"

REM Configuration (set by build script or edit manually)
if "%NG_BASE_URL%"=="" set "BASE_URL=__BASE_URL__"
if not "%NG_BASE_URL%"=="" set "BASE_URL=%NG_BASE_URL%"
if "%NG_FLEET_KEY%"=="" set "FLEET_KEY=__FLEET_KEY__"
if not "%NG_FLEET_KEY%"=="" set "FLEET_KEY=%NG_FLEET_KEY%"
if "%NG_INTERVAL%"=="" set "INTERVAL=60"
if not "%NG_INTERVAL%"=="" set "INTERVAL=%NG_INTERVAL%"

echo.
echo ========================================================
echo    NETWORK GUARDIAN — FIELD AGENT SETUP
echo    WOLFPAK INTERNAL USE ONLY
echo ========================================================
echo.

REM Find Python
set "PYTHON="
where python3 >nul 2>&1 && set "PYTHON=python3"
if "%PYTHON%"=="" where python >nul 2>&1 && set "PYTHON=python"

if "%PYTHON%"=="" (
    echo   ERROR: Python 3.11+ is required but not found.
    echo   Install from https://python.org/downloads/
    pause
    exit /b 1
)

REM Check version
for /f "tokens=*" %%i in ('%PYTHON% -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"') do set "PYVER=%%i"
echo   Python: %PYVER%
echo   Base:   %BASE_URL%
echo.

REM Create agent directory
if not exist "%AGENT_DIR%" mkdir "%AGENT_DIR%"

REM Copy probe
copy /Y "%SCRIPT_DIR%probe.py" "%AGENT_DIR%\probe.py" >nul

REM Wolfpak auth (first run)
echo   Authenticating with Wolfpak base station...
%PYTHON% "%AGENT_DIR%\probe.py" --base "%BASE_URL%" --key "%FLEET_KEY%" --once --no-discovery 2>nul

REM Install as scheduled task
echo.
echo   Installing auto-start task...
schtasks /Delete /TN "NetworkGuardianProbe" /F >nul 2>&1
schtasks /Create /TN "NetworkGuardianProbe" /TR "\"%PYTHON%\" \"%AGENT_DIR%\probe.py\" --base \"%BASE_URL%\" --key \"%FLEET_KEY%\" --interval %INTERVAL%" /SC ONLOGON /RL HIGHEST /F >nul 2>&1

if %errorlevel%==0 (
    echo   [OK] Windows scheduled task installed — agent starts on login
    REM Start now
    schtasks /Run /TN "NetworkGuardianProbe" >nul 2>&1
) else (
    echo   [WARNING] Could not create scheduled task.
    echo   Try right-clicking setup.bat and selecting "Run as Administrator"
)

echo.
echo ========================================================
echo    SETUP COMPLETE — AGENT ACTIVE
echo.
echo    The agent is now monitoring this network and
echo    reporting to the Wolfpak base station.
echo.
echo    It will auto-start every time you log in.
echo.
echo    To uninstall:
echo      %PYTHON% "%AGENT_DIR%\probe.py" --uninstall
echo ========================================================
echo.
pause
