# AetherLink Windows uninstall: exact inverse of install.ps1.
# Runs cleanup first (routes/DNS restored), then removes everything.
$ErrorActionPreference = "Stop"

$InstallDir = if ($env:AETHERLINK_DIR) { $env:AETHERLINK_DIR } else { "$env:ProgramFiles\AetherLink" }
$StateDir = "$env:ProgramData\AetherLink"

if (Test-Path -LiteralPath "$InstallDir\client\AetherLink.Client.exe") {
    & "$InstallDir\client\AetherLink.Client.exe" "$InstallDir\client.example.yaml" cleanup
}

Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $StateDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Output "AetherLink uninstalled (binaries, configs and state removed)."
