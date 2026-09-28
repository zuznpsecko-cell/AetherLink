<# 
.SYNOPSIS
Verify AetherLink client live against VPS (DNS + HTTP through tunnel).

.PREREQUISITES
- Run as Administrator (PowerShell)
- V2RayN / other TUN users MUST BE OFF
- dist\win-client\AetherLink.Client.exe + wintun.dll present
- client.local.yaml configured for VPS

.OUTPUTS
- logs\up-out.txt, up-err.txt, probe.txt, curl.txt, down.txt
- Exit code 0 = all green
#>
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$env:AETHERLINK_DEBUG = '1'
$ROOT   = $PSScriptRoot | Split-Path -Parent
$CLIENT = "$ROOT\dist\win-client\AetherLink.Client.exe"
$CFG    = "$ROOT\client.local.yaml"
$LOG    = "$ROOT\logs"
$PY     = "python"  # or full path if not in PATH

# ---- sanity ----
if (-not (Test-Path $CLIENT)) { Write-Error "Client not found: $CLIENT"; exit 1 }
if (-not (Test-Path $CFG))    { Write-Error "Config not found: $CFG"; exit 1 }
if (-not (Test-Path "$ROOT\dist\win-client\wintun.dll")) { Write-Error "wintun.dll missing"; exit 1 }
New-Item -ItemType Directory -Force -Path $LOG | Out-Null

# ---- kill any stale + clear stale up-state (killed up orphans it) ----
Stop-Process -Name "AetherLink.Client" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
# NOTE: via cmd — PS 5.1 cannot silence native stderr (not even *>$null).
cmd /c "`"$CLIENT`" `"$CFG`" down >nul 2>&1"
cmd /c "`"$CLIENT`" `"$CFG`" cleanup >nul 2>&1"
Start-Sleep -Seconds 1

try {
  # ---- UP ----
  Write-Host "=== UP ===" -ForegroundColor Cyan
  Start-Process -FilePath $CLIENT -ArgumentList "$CFG up" `
    -RedirectStandardOutput "$LOG\up-out.txt" -RedirectStandardError "$LOG\up-err.txt"

  $deadline = (Get-Date).AddSeconds(120)
  while (-not (Select-String "Tunnel up" "$LOG\up-out.txt" -Quiet -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) { throw "Tunnel up timeout (>120s)" }
    Start-Sleep -Seconds 2
  }
  Write-Host "Tunnel up" -ForegroundColor Green

  # ---- DNS probe (authoritative, txid check) ----
  Write-Host "=== DNS probe ===" -ForegroundColor Cyan
  $pyScript = @'
import socket, sys
q = bytes.fromhex('123401000001000000000000') + b'\x07example\x03com\x00' + bytes.fromhex('00010001')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(10)
s.sendto(q, ('10.255.0.1', 53))
data, addr = s.recvfrom(512)
ok = data[:2] == b'\x12\x34'
print(f'from {addr} len {len(data)} txid-ok {ok}')
print(data.hex())
sys.exit(0 if ok else 1)
'@
  $pyScript | Out-File -Encoding utf8 "$LOG\dns_probe.py"
  # NOTE: cmd redirection (not 2>&1 | Out-File) — PS 5.1 mangles native stderr.
  cmd /c "python `"$LOG\dns_probe.py`" > `"$LOG\probe.txt`" 2>&1"
  if ($LASTEXITCODE -ne 0) { Get-Content "$LOG\probe.txt"; throw "DNS FAIL (see logs\probe.txt)" }
  Write-Host "DNS OK" -ForegroundColor Green

  # ---- HTTP through tunnel ----
  Write-Host "=== HTTP curl ===" -ForegroundColor Cyan
  curl.exe -4 -s http://example.com/ --max-time 25 2>&1 | Out-File -Encoding utf8 "$LOG\curl.txt"
  $curlOut = Get-Content "$LOG\curl.txt" -Raw -Encoding utf8
  if ($curlOut -notmatch '<!doctype html>') {
    Get-Content "$LOG\curl.txt"
    throw "HTTP FAIL (see logs\curl.txt)"
  }
  Write-Host "HTTP OK (HTML received)" -ForegroundColor Green

  Write-Host "=== ALL GREEN ===" -ForegroundColor Green
  exit 0
}
finally {
  # ---- DOWN (always: restores DNS/routes even on failure) ----
  Write-Host "=== DOWN ===" -ForegroundColor Cyan
  try { & $CLIENT $CFG down 2>$null | Out-File "$LOG\down.txt" } catch { "down cmd failed: $_" | Out-File "$LOG\down.txt" }
  Stop-Process -Name "AetherLink.Client" -ErrorAction SilentlyContinue
  Write-Host "(tunnel down, network/DNS restored)" -ForegroundColor DarkGray
}