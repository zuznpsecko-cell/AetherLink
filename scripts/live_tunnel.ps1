<#
.SYNOPSIS
Bring the live tunnel up against VPS and prove traffic goes through it.

Checks: admin, V2RayN off, stale cleanup, DNS self-heal, up, then shows
routes + DNS + egress IP (must equal the VPS address). Enter brings it
down (always, even on Ctrl+C / failure).

Run ELEVATED (admin), V2RayN OFF:
  .\scripts\live_tunnel.ps1 [-Config client.local.yaml]
#>
[CmdletBinding()]
param(
  [string]$Config = "client.local.yaml",
  [switch]$DebugLog
)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

# Debug logging is per-packet synchronous I/O: it skews latency/throughput
# badly under load (speedtests). Off by default; pass -DebugLog to capture logs.
if ($DebugLog) { $env:AETHERLINK_DEBUG = '1' } else { $env:AETHERLINK_DEBUG = '0' }
$ROOT   = $PSScriptRoot | Split-Path -Parent
$CLIENT = "$ROOT\dist\win-client\AetherLink.Client.exe"
$CFG    = Join-Path $ROOT $Config
$LOG    = "$ROOT\logs"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error "Restart elevated: TUN + routes + DNS need admin."; exit 1 }
if (-not (Test-Path $CLIENT)) { Write-Error "Client not found: $CLIENT"; exit 1 }
if (-not (Test-Path $CFG)) { Write-Error "Config not found: $CFG"; exit 1 }
if (Get-Process "v2rayN" -ErrorAction SilentlyContinue) {
  Write-Host "NOTE: v2rayN app is running (ok as long as its TUN is off)" -ForegroundColor Yellow
}
# Fail only on a FOREIGN active TUN (it would steal default routes).
# Our own stale aether0 is excluded (torn down in pre-clean below).
$foreignTun = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
  $_.Status -eq 'Up' -and $_.Name -ne 'aether0' -and
  ($_.InterfaceDescription -match 'tun|sing-box|wintun|wireguard|tap-windows|nekoray|v2ray|clash|mihomo' -or
   $_.Name -match 'tun|sing-box|wintun|wireguard')
}
if ($foreignTun) {
  $names = ($foreignTun | ForEach-Object { $_.Name }) -join ', '
  Write-Error "Foreign TUN active ($names) - disable it first (routes would clash)."; exit 1
}
New-Item -ItemType Directory -Force -Path $LOG | Out-Null

# VPS address from config (for the egress proof).
$VPS = (Select-String -Pattern 'server_addr:\s*(\S+)' -Path $CFG | Select-Object -First 1).Matches.Groups[1].Value -replace '["'']','' -replace ':.*$',''
Write-Host "VPS: $VPS" -ForegroundColor DarkGray

try {
  # ---- pre-clean ----
  Stop-Process -Name "AetherLink.Client" -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
  cmd /c "`"$CLIENT`" `"$CFG`" down >nul 2>&1"
  cmd /c "`"$CLIENT`" `"$CFG`" cleanup >nul 2>&1"
  $stale = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.ServerAddresses -contains '10.255.0.1' }
  foreach ($s in $stale) {
    Write-Host "Resetting stale tunnel DNS on $($s.InterfaceAlias)" -ForegroundColor Yellow
    Set-DnsClientServerAddress -InterfaceIndex $s.InterfaceIndex -ResetServerAddresses
  }

  # ---- up ----
  Write-Host "=== UP ===" -ForegroundColor Cyan
  Start-Process -FilePath $CLIENT -ArgumentList "`"$CFG`" up" `
    -RedirectStandardOutput "$LOG\up-out.txt" -RedirectStandardError "$LOG\up-err.txt"
  $deadline = (Get-Date).AddSeconds(120)
  while (-not (Select-String "Tunnel up" "$LOG\up-out.txt" -Quiet -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) { throw "Tunnel up timeout (>120s)" }
    Start-Sleep -Seconds 2
  }
  Write-Host "Tunnel up" -ForegroundColor Green

  # ---- proof: routes ----
  Write-Host "=== Routes (/1 via TUN?) ===" -ForegroundColor Cyan
  Get-NetRoute -DestinationPrefix "0.0.0.0/1" -ErrorAction SilentlyContinue |
    Format-Table DestinationPrefix, NextHop, RouteMetric -AutoSize | Out-String | Write-Host
  Get-NetRoute -DestinationPrefix "128.0.0.0/1" -ErrorAction SilentlyContinue |
    Format-Table DestinationPrefix, NextHop, RouteMetric -AutoSize | Out-String | Write-Host

  # ---- proof: DNS ----
  Write-Host "=== DNS (tunnel resolver?) ===" -ForegroundColor Cyan
  Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.ServerAddresses } |
    Format-Table InterfaceAlias, ServerAddresses -AutoSize | Out-String | Write-Host

  # ---- proof: egress IP (must be the VPS) ----
  # NOTE: plain HTTP (port 80, one small response) — the proven path.
  Write-Host "=== Egress IP (must be $VPS) ===" -ForegroundColor Cyan
  $raw = curl.exe -4 -s --max-time 15 http://ifconfig.me 2>$null
  $ip = if ($raw) { $raw.Trim() } else { "" }
  if ($ip -eq $VPS) {
    Write-Host "Egress: $ip - ALL TRAFFIC VIA TUNNEL" -ForegroundColor Green
  } elseif ($ip -eq "") {
    Write-Host "Egress check failed (empty reply) - see logs" -ForegroundColor Red
  } else {
    Write-Host "Egress: $ip - MISMATCH (expected $VPS)" -ForegroundColor Red
  }

  Write-Host ""
  Write-Host "Tunnel LIVE. Browse / test freely. Press Enter to bring it down." -ForegroundColor Green
  Read-Host | Out-Null
}
finally {
  Write-Host "=== DOWN ===" -ForegroundColor Cyan
  cmd /c "`"$CLIENT`" `"$CFG`" down > `"$LOG\down.txt`" 2>&1"
  Stop-Process -Name "AetherLink.Client" -ErrorAction SilentlyContinue
  Get-Content "$LOG\down.txt" -ErrorAction SilentlyContinue | Select-Object -First 2
  Write-Host "(tunnel down, network/DNS restored)" -ForegroundColor DarkGray
}
