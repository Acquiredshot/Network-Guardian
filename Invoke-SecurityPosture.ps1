#Requires -Version 5.1
<#
.SYNOPSIS
    Invoke-SecurityPosture.ps1 - Read-only Windows security posture auditor.

.DESCRIPTION
    Runs a registry of independent, weighted security checks and produces a
    scored posture report. Each check is fully isolated: one failing check can
    never crash the run. The tool is strictly READ-ONLY - it assesses, it never
    changes system state.

    Output: color-coded console report + optional self-contained HTML report.

.PARAMETER Html
    Export a styled HTML report to the given path (or the desktop by default).

.PARAMETER MinSeverity
    Only display checks at or above this status in the console (Fail, Warn, Pass).

.EXAMPLE
    .\Invoke-SecurityPosture.ps1
    .\Invoke-SecurityPosture.ps1 -Html
    .\Invoke-SecurityPosture.ps1 -Html "C:\Reports\posture.html" -MinSeverity Warn
#>

[CmdletBinding()]
param(
    [string]$Html,
    [ValidateSet('Pass', 'Warn', 'Fail')]
    [string]$MinSeverity = 'Pass'
)

#region ---- Result contract --------------------------------------------------

# Every check returns one of these. Keeping the shape uniform is what lets the
# runner, scorer, console renderer, and HTML renderer all stay dumb and generic.
function New-CheckResult {
    param(
        [ValidateSet('Pass', 'Warn', 'Fail', 'Info', 'Unknown')]
        [string]$Status,
        [string]$Detail,
        [string]$Fix = ''
    )
    [pscustomobject]@{ Status = $Status; Detail = $Detail; Fix = $Fix }
}

#endregion

#region ---- Check registry ---------------------------------------------------
# Each check: Name, Category, Weight, and a Test scriptblock returning a result.
# Add a check by appending an object here - nothing else needs to change.

$Checks = @(
    [pscustomobject]@{
        Name = 'Defender real-time protection'; Category = 'Endpoint'; Weight = 10
        Test = {
            $s = Get-MpComputerStatus -ErrorAction Stop
            if ($s.RealTimeProtectionEnabled) { New-CheckResult Pass "Real-time protection is ON" }
            else { New-CheckResult Fail "Real-time protection is OFF" "Enable Microsoft Defender real-time protection" }
        }
    }
    [pscustomobject]@{
        Name = 'Defender signature age'; Category = 'Endpoint'; Weight = 6
        Test = {
            $s = Get-MpComputerStatus -ErrorAction Stop
            $age = $s.AntivirusSignatureAge
            if ($age -le 2)      { New-CheckResult Pass "Signatures updated $age day(s) ago" }
            elseif ($age -le 7)  { New-CheckResult Warn "Signatures are $age days old" "Run a definition update" }
            else                 { New-CheckResult Fail "Signatures are $age days old" "Definitions are stale; update now" }
        }
    }
    [pscustomobject]@{
        Name = 'Firewall (all profiles)'; Category = 'Network'; Weight = 10
        Test = {
            $off = Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled }
            if (-not $off) { New-CheckResult Pass "Domain, Private and Public profiles enabled" }
            else { New-CheckResult Fail ("Disabled profile(s): " + ($off.Name -join ', ')) "Enable the firewall on all profiles" }
        }
    }
    [pscustomobject]@{
        Name = 'BitLocker (system drive)'; Category = 'Data'; Weight = 8
        Test = {
            $sys = $env:SystemDrive
            $v = Get-BitLockerVolume -MountPoint $sys -ErrorAction Stop
            switch ($v.ProtectionStatus) {
                'On'  { New-CheckResult Pass "$sys is encrypted and protected" }
                default { New-CheckResult Fail "$sys is not protected by BitLocker" "Enable BitLocker on the system drive" }
            }
        }
    }
    [pscustomobject]@{
        Name = 'Secure Boot'; Category = 'Boot'; Weight = 6
        Test = {
            try {
                if (Confirm-SecureBootUEFI -ErrorAction Stop) { New-CheckResult Pass "Secure Boot is enabled" }
                else { New-CheckResult Warn "Secure Boot is supported but OFF" "Enable Secure Boot in UEFI" }
            } catch { New-CheckResult Info "Legacy BIOS or Secure Boot unsupported" }
        }
    }
    [pscustomobject]@{
        Name = 'UAC enabled'; Category = 'Access'; Weight = 6
        Test = {
            $k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
            if ($k.EnableLUA -eq 1) { New-CheckResult Pass "User Account Control is enabled" }
            else { New-CheckResult Fail "UAC is disabled" "Re-enable UAC (EnableLUA = 1)" }
        }
    }
    [pscustomobject]@{
        Name = 'SMBv1 protocol'; Category = 'Network'; Weight = 8
        Test = {
            $c = Get-SmbServerConfiguration -ErrorAction Stop
            if (-not $c.EnableSMB1Protocol) { New-CheckResult Pass "SMBv1 is disabled" }
            else { New-CheckResult Fail "SMBv1 is ENABLED (legacy, exploitable)" "Disable SMBv1" }
        }
    }
    [pscustomobject]@{
        Name = 'RDP exposure'; Category = 'Access'; Weight = 8
        Test = {
            $deny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop).fDenyTSConnections
            if ($deny -eq 1) { return New-CheckResult Pass "RDP is disabled" }
            $nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication
            if ($nla -eq 1) { New-CheckResult Warn "RDP is enabled (NLA on)" "Confirm RDP exposure is intended; restrict to VPN/known IPs" }
            else { New-CheckResult Fail "RDP enabled WITHOUT Network Level Authentication" "Enable NLA or disable RDP" }
        }
    }
    [pscustomobject]@{
        Name = 'Guest account'; Category = 'Access'; Weight = 4
        Test = {
            $g = Get-LocalUser -Name 'Guest' -ErrorAction Stop
            if (-not $g.Enabled) { New-CheckResult Pass "Guest account is disabled" }
            else { New-CheckResult Fail "Guest account is enabled" "Disable the Guest account" }
        }
    }
    [pscustomobject]@{
        Name = 'Local administrators'; Category = 'Access'; Weight = 6
        Test = {
            $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
            $n = @($admins).Count
            $names = ($admins.Name | ForEach-Object { $_.Split('\\')[-1] }) -join ', '
            if ($n -le 2) { New-CheckResult Pass "$n admin account(s): $names" }
            else { New-CheckResult Warn "$n admin accounts: $names" "Review whether all need admin rights" }
        }
    }
    [pscustomobject]@{
        Name = 'Stale local passwords'; Category = 'Access'; Weight = 4
        Test = {
            $cut = (Get-Date).AddDays(-180)
            $stale = Get-LocalUser -ErrorAction Stop |
                Where-Object { $_.Enabled -and $_.PasswordLastSet -and $_.PasswordLastSet -lt $cut }
            if (-not $stale) { New-CheckResult Pass "No enabled account has a password older than 180 days" }
            else { New-CheckResult Warn ("Old passwords: " + ($stale.Name -join ', ')) "Rotate credentials older than 180 days" }
        }
    }
    [pscustomobject]@{
        Name = 'Externally-bound listeners'; Category = 'Network'; Weight = 6
        Test = {
            $listen = Get-NetTCPConnection -State Listen -ErrorAction Stop |
                Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' }
            $ports = ($listen.LocalPort | Sort-Object -Unique)
            if (@($ports).Count -eq 0) { New-CheckResult Pass "No non-loopback TCP listeners" }
            else { New-CheckResult Info ("Listening on: " + ($ports -join ', ')) "Confirm each open port is intentional" }
        }
    }
    [pscustomobject]@{
        Name = 'Patch recency'; Category = 'Updates'; Weight = 8
        Test = {
            $last = (Get-HotFix -ErrorAction Stop | Where-Object InstalledOn | Sort-Object InstalledOn | Select-Object -Last 1).InstalledOn
            if (-not $last) { return New-CheckResult Unknown "Could not determine last update date" }
            $days = (New-TimeSpan -Start $last -End (Get-Date)).Days
            if ($days -le 35)     { New-CheckResult Pass "Last update $days day(s) ago ($($last.ToShortDateString()))" }
            elseif ($days -le 60) { New-CheckResult Warn "Last update $days days ago" "Check Windows Update" }
            else                  { New-CheckResult Fail "Last update $days days ago" "System is behind on patches" }
        }
    }
    [pscustomobject]@{
        Name = 'Pending reboot'; Category = 'Updates'; Weight = 3
        Test = {
            $paths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
            )
            if ($paths | Where-Object { Test-Path $_ }) { New-CheckResult Warn "A reboot is pending" "Reboot to finish applying updates" }
            else { New-CheckResult Pass "No pending reboot" }
        }
    }
    [pscustomobject]@{
        Name = 'PowerShell execution policy'; Category = 'Access'; Weight = 3
        Test = {
            $p = Get-ExecutionPolicy
            if ($p -in 'Restricted', 'AllSigned', 'RemoteSigned') { New-CheckResult Pass "Execution policy is '$p'" }
            else { New-CheckResult Warn "Execution policy is '$p'" "Consider RemoteSigned for everyday use" }
        }
    }
)

#endregion

#region ---- Runner (isolates every check) -----------------------------------

function Invoke-Checks {
    param($Registry)
    foreach ($c in $Registry) {
        $start = Get-Date
        try   { $r = & $c.Test }
        catch { $r = New-CheckResult Unknown "Check error: $($_.Exception.Message)" }
        [pscustomobject]@{
            Name     = $c.Name
            Category = $c.Category
            Weight   = $c.Weight
            Status   = $r.Status
            Detail   = $r.Detail
            Fix      = $r.Fix
            Ms       = [int]((Get-Date) - $start).TotalMilliseconds
        }
    }
}

function Get-PostureScore {
    param($Results)
    $scored = $Results | Where-Object { $_.Status -in 'Pass', 'Warn', 'Fail' }
    $max    = ($scored | Measure-Object Weight -Sum).Sum
    if (-not $max) { return [pscustomobject]@{ Percent = 0; Grade = 'N/A' } }
    $earned = 0
    foreach ($r in $scored) {
        switch ($r.Status) { 'Pass' { $earned += $r.Weight } 'Warn' { $earned += $r.Weight * 0.5 } }
    }
    $pct = [math]::Round(($earned / $max) * 100)
    if ($pct -ge 90) {
        $grade = 'A'
    }
    elseif ($pct -ge 80) {
        $grade = 'B'
    }
    elseif ($pct -ge 70) {
        $grade = 'C'
    }
    elseif ($pct -ge 60) {
        $grade = 'D'
    }
    else {
        $grade = 'F'
    }
    [pscustomobject]@{ Percent = $pct; Grade = $grade; Earned = $earned; Max = $max }
}

#endregion

#region ---- Console renderer -------------------------------------------------

$Glyph = @{ Pass='[+]'; Warn='[!]'; Fail='[x]'; Info='[i]'; Unknown='[?]' }
$Color = @{ Pass='Green'; Warn='Yellow'; Fail='Red'; Info='Cyan'; Unknown='DarkGray' }
$Rank  = @{ Fail=0; Warn=1; Pass=2; Info=3; Unknown=4 }

$results = Invoke-Checks -Registry $Checks
$score   = Get-PostureScore -Results $results

Write-Host ""
Write-Host "  ##############################################################" -ForegroundColor DarkCyan
Write-Host "  #            WINDOWS SECURITY POSTURE  -  AUDIT              #" -ForegroundColor DarkCyan
Write-Host "  ##############################################################" -ForegroundColor DarkCyan
Write-Host ("   Host: {0}    User: {1}    {2}" -f $env:COMPUTERNAME, $env:USERNAME, (Get-Date)) -ForegroundColor DarkGray
Write-Host ""

$minRank = $Rank[$MinSeverity]
foreach ($cat in ($results | Select-Object -Expand Category -Unique)) {
    Write-Host "  $cat" -ForegroundColor White
    foreach ($r in ($results | Where-Object Category -eq $cat | Sort-Object { $Rank[$_.Status] })) {
        if ($Rank[$r.Status] -gt $minRank -and $r.Status -in 'Pass') { continue }
        Write-Host ("    {0} {1,-32} {2}" -f $Glyph[$r.Status], $r.Name, $r.Detail) -ForegroundColor $Color[$r.Status]
        if ($r.Fix -and $r.Status -in 'Fail', 'Warn') {
            Write-Host ("        -> $($r.Fix)") -ForegroundColor DarkGray
        }
    }
    Write-Host ""
}

$bar = ('#' * [math]::Round($score.Percent / 5)).PadRight(20, '.')
$sc  = if ($score.Percent -ge 80) {'Green'} elseif ($score.Percent -ge 60) {'Yellow'} else {'Red'}
Write-Host "  --------------------------------------------------------------" -ForegroundColor DarkCyan
Write-Host ("   POSTURE SCORE  [{0}]  {1}%   Grade: {2}" -f $bar, $score.Percent, $score.Grade) -ForegroundColor $sc
$counts = $results | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
Write-Host ("   Breakdown: " + ($counts -join '  ')) -ForegroundColor DarkGray
Write-Host ""

#endregion

#region ---- HTML report ------------------------------------------------------

if ($PSBoundParameters.ContainsKey('Html')) {
    if (-not $Html) { $Html = Join-Path ([Environment]::GetFolderPath('Desktop')) 'SecurityPosture.html' }

    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $rows = foreach ($r in ($results | Sort-Object { $Rank[$_.Status] })) {
        $fix = if ($r.Fix) { [System.Web.HttpUtility]::HtmlEncode($r.Fix) } else { '&mdash;' }
        @"
<tr class="s-$($r.Status.ToLower())">
  <td>$([System.Web.HttpUtility]::HtmlEncode($r.Category))</td>
  <td>$([System.Web.HttpUtility]::HtmlEncode($r.Name))</td>
  <td><span class="badge">$($r.Status)</span></td>
  <td>$([System.Web.HttpUtility]::HtmlEncode($r.Detail))</td>
  <td class="fix">$fix</td>
</tr>
"@
    }

    $html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Security Posture</title>
<style>
  :root{color-scheme:dark}
  body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:40px}
  h1{font-size:22px;margin:0 0 4px} .sub{color:#7d8590;margin-bottom:24px}
  .score{display:inline-block;font-size:40px;font-weight:700;padding:14px 26px;border-radius:14px;background:#161b22;border:1px solid #30363d}
  .g-A,.g-B{color:#3fb950}.g-C,.g-D{color:#d29922}.g-F{color:#f85149}
  table{width:100%;border-collapse:collapse;margin-top:24px;background:#161b22;border-radius:10px;overflow:hidden}
  th,td{text-align:left;padding:10px 14px;border-bottom:1px solid #21262d}
  th{background:#1c2128;color:#7d8590;text-transform:uppercase;font-size:11px;letter-spacing:.5px}
  .fix{color:#7d8590}
  .badge{font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px}
  .s-pass .badge{background:#13351f;color:#3fb950}.s-warn .badge{background:#3a2d10;color:#d29922}
  .s-fail .badge{background:#3d1418;color:#f85149}.s-info .badge{background:#10293a;color:#58a6ff}
  .s-unknown .badge{background:#21262d;color:#7d8590}
</style></head><body>
<h1>Windows Security Posture</h1>
<div class="sub">$($env:COMPUTERNAME) &middot; $($env:USERNAME) &middot; $(Get-Date)</div>
<div class="score g-$($score.Grade)">$($score.Percent)% &middot; $($score.Grade)</div>
<table><thead><tr><th>Category</th><th>Check</th><th>Status</th><th>Detail</th><th>Recommendation</th></tr></thead>
<tbody>$($rows -join "`n")</tbody></table>
</body></html>
"@
    $html | Out-File -FilePath $Html -Encoding UTF8
    Write-Host "  HTML report written to: $Html" -ForegroundColor Green
    Write-Host ""
}

#endregion
