# Network Guardian - Complete Local Startup (Windows PowerShell)
# Run this file to start the entire application
# Usage: .\Start-All.ps1

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  Network Guardian - Complete Local Application (Windows)" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Starting all services..." -ForegroundColor Green
Write-Host ""
Write-Host "Dashboard: http://127.0.0.1:8080" -ForegroundColor Yellow
Write-Host "Login: admin / <password>" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Ctrl+C to stop all services." -ForegroundColor Magenta
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Get the directory where this script is located
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Run the Python startup script
& python start_all.py

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: Failed to start Network Guardian" -ForegroundColor Red
    Write-Host "Make sure you have Python 3.9+ installed and in your PATH" -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}
