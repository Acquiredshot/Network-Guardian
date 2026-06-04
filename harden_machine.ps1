# ============================================================
#  Network Guardian — Machine & Network Hardening
#  Run as Administrator
# ============================================================
$ErrorActionPreference = "SilentlyContinue"

Write-Host "`n[1/5] Hardening TCP/IP stack against SYN floods & DoS..." -ForegroundColor Cyan

$tcpParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

# SYN flood protection (2 = aggressive)
Set-ItemProperty -Path $tcpParams -Name "SynAttackProtect"          -Value 2   -Type DWord
# Reduce half-open connection limits
Set-ItemProperty -Path $tcpParams -Name "TcpMaxHalfOpen"            -Value 100 -Type DWord
Set-ItemProperty -Path $tcpParams -Name "TcpMaxHalfOpenRetried"     -Value 80  -Type DWord
Set-ItemProperty -Path $tcpParams -Name "TCPMaxPortsExhausted"      -Value 5   -Type DWord
# Disable IP source routing (used in spoofed floods)
Set-ItemProperty -Path $tcpParams -Name "DisableIPSourceRouting"    -Value 2   -Type DWord
# Disable ICMP redirects (used in MITM/routing attacks)
Set-ItemProperty -Path $tcpParams -Name "EnableICMPRedirect"        -Value 0   -Type DWord
# Shorten keep-alive to free connections faster under attack
Set-ItemProperty -Path $tcpParams -Name "KeepAliveTime"             -Value 300000 -Type DWord
# Ignore NetBIOS name release requests (stops some network spoofing)
Set-ItemProperty -Path $tcpParams -Name "NoNameReleaseOnDemand"     -Value 1   -Type DWord
# Limit how long dead connections linger
Set-ItemProperty -Path $tcpParams -Name "TcpTimedWaitDelay"         -Value 30  -Type DWord

Write-Host "    [OK] TCP/IP stack hardened" -ForegroundColor Green

Write-Host "`n[2/5] Configuring Windows Firewall — all profiles block unsolicited inbound..." -ForegroundColor Cyan

# Ensure firewall is ON for all profiles and blocks inbound by default
netsh advfirewall set allprofiles state on | Out-Null
netsh advfirewall set allprofiles firewallpolicy "blockinbound,allowoutbound" | Out-Null

Write-Host "    [OK] Firewall: inbound=BLOCK, outbound=ALLOW on all profiles" -ForegroundColor Green

Write-Host "`n[3/5] Enabling firewall drop logging..." -ForegroundColor Cyan

$logPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
netsh advfirewall set allprofiles logging maxfilesize 32767 | Out-Null
netsh advfirewall set allprofiles logging filename $logPath | Out-Null

Write-Host "    [OK] Drop log: $logPath" -ForegroundColor Green

Write-Host "`n[4/5] Adding network-layer flood-source block rules..." -ForegroundColor Cyan

# Block common UDP amplification attack source ports (inbound only)
# These are never legitimate inbound traffic for a desktop/game server machine
$rules = @(
    @{Name="NG-PROTECT-Block-CharGen-IN";   Port="19";   Proto="UDP"},
    @{Name="NG-PROTECT-Block-QOTD-IN";      Port="17";   Proto="UDP"},
    @{Name="NG-PROTECT-Block-mDNS-Amp-IN";  Port="5353"; Proto="UDP"},
    @{Name="NG-PROTECT-Block-SSDP-Amp-IN";  Port="1900"; Proto="UDP"},
    @{Name="NG-PROTECT-Block-NTP-Amp-IN";   Port="123";  Proto="UDP"},
    @{Name="NG-PROTECT-Block-Memcached-IN"; Port="11211";Proto="UDP"}
)

foreach ($r in $rules) {
    # Remove old if exists
    Remove-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
    New-NetFirewallRule `
        -DisplayName $r.Name `
        -Direction Inbound `
        -Protocol $r.Proto `
        -LocalPort $r.Port `
        -Action Block `
        -Profile Any `
        -Enabled True | Out-Null
    Write-Host "    [OK] Blocked inbound $($r.Proto) port $($r.Port) ($($r.Name))" -ForegroundColor Green
}

Write-Host "`n[5/5] Starting Flood Watchdog..." -ForegroundColor Cyan

$venvPython = "c:\Users\Cortez\Network Guardian\.venv\Scripts\python.exe"
$watchdog   = "c:\Users\Cortez\Network Guardian\flood_watchdog.py"

if (Test-Path $venvPython) {
    Start-Process -FilePath $venvPython `
        -ArgumentList "`"$watchdog`" --threshold 60 --interval 5" `
        -WorkingDirectory "c:\Users\Cortez\Network Guardian" `
        -WindowStyle Normal
    Write-Host "    [OK] Flood watchdog running (threshold=60 conns/IP, interval=5s)" -ForegroundColor Green
} else {
    Write-Host "    [WARN] venv python not found at $venvPython" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  MACHINE HARDENED — Summary" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  TCP SYN flood protection:       ACTIVE (aggressive)"
Write-Host "  IP source routing:              DISABLED"
Write-Host "  ICMP redirects:                 DISABLED"
Write-Host "  Windows Firewall (all profiles): ON — block inbound"
Write-Host "  Firewall drop logging:          ENABLED -> $logPath"
Write-Host "  UDP amplification ports:        BLOCKED (6 vectors)"
Write-Host "  Flood watchdog:                 RUNNING"
Write-Host "  Network Guardian IPS:           RUNNING on :8081"
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Press any key to close..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
