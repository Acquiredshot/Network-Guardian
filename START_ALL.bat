@echo off
REM Network Guardian - Complete Local Startup (Windows)
REM Run this file to start the entire application
REM Or use: python start_all.py

setlocal enabledelayedexpansion

echo ================================================================================
echo   Network Guardian - Complete Local Application (Windows)
echo ================================================================================
echo.
echo Starting all services...
echo.
echo Dashboard: http://127.0.0.1:8080
echo Login: admin / <password>
echo.
echo Press Ctrl+C to stop all services.
echo.
echo ================================================================================
echo.

cd /d "%~dp0"
python start_all.py

if errorlevel 1 (
    echo.
    echo ERROR: Failed to start Network Guardian
    echo Make sure you have Python 3.9+ installed
    echo.
    pause
    exit /b 1
)

pause
