# AetherLink Windows deploy (personal, from scratch).
# Installs the PUBLISHED hosts from dist/ (see scripts/run_*_windows.ps1),
# stages wintun.dll side-by-side with the client (v2rayN-style),
# snapshots DNS (NRPT/interface) and leaves force_cleanup for crash recovery.
$ErrorActionPreference = "Stop"

$PssRoot = Split-Path -Parent $PSScriptRoot
$RepoRoot = Split-Path -Parent $PssRoot
$InstallDir = if ($env:AETHERLINK_DIR) { $env:AETHERLINK_DIR } else { "$env:ProgramFiles\AetherLink" }
$StateDir = "$env:ProgramData\AetherLink"
$StateFile = "$StateDir\state.json"

New-Item -ItemType Directory -Force -Path "$InstallDir\server", "$InstallDir\client", $StateDir | Out-Null
Copy-Item -Force "$RepoRoot\dist\win-server\*" "$InstallDir\server" -Recurse
Copy-Item -Force "$RepoRoot\dist\win-client\*" "$InstallDir\client" -Recurse
foreach ($cfg in @("client.example.yaml", "server.example.yaml")) {
    if (-not (Test-Path -LiteralPath "$InstallDir\$cfg")) {
        Copy-Item -Force "$RepoRoot\configs\$cfg" "$InstallDir\$cfg"
    }
}

# Wintun: wintun.dll must sit next to the CLIENT exe; the core loads it from
# the host directory (client.wintun_dll_path). Version pinned in DECISIONS (0.14.1).
if (Test-Path -LiteralPath "$RepoRoot\wintun.dll") {
    Copy-Item -Force "$RepoRoot\wintun.dll" "$InstallDir\client"
} elseif (-not (Test-Path -LiteralPath "$InstallDir\client\wintun.dll")) {
    Write-Warning "wintun.dll not found; place it in $InstallDir\client (see https://www.wintun.net/)."
}

# DNS snapshot (interface DNS + NRPT) so force_cleanup can restore after crash.
Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Export-Clixml -Path "$StateDir\dns.snapshot.xml" -Force

# Idempotent cleanup: restores routes + DNS (NRPT/interface) from $StateFile.
& "$InstallDir\client\AetherLink.Client.exe" "$InstallDir\client.example.yaml" cleanup

Write-Output "AetherLink installed to $InstallDir (server/ + client/). Uninstall: .\deploy\windows\uninstall.ps1"
