# Quickstart: AetherLink client (full tunnel) on Windows. Run ELEVATED (admin):
#   .\scripts\run_client_windows.ps1 [-Config <path>]
# Builds core, publishes thin host, stages wintun.dll side-by-side, brings the
# tunnel up. Ctrl+C / exit triggers down + force_cleanup (routes/DNS restored).
[CmdletBinding()]
param(
    [string]$Config = "configs/client.example.yaml",
    [string]$OutDir = "dist/win-client"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Restart elevated: TUN/Wintun + default-route changes require admin."
}

Write-Output "==> Building Rust core (aetherlink-ffi cdylib, release)..."
cargo build --release -p aetherlink-ffi

Write-Output "==> Publishing thin .NET client host (win-x64, self-contained)..."
dotnet publish dotnet/AetherLink.Client/AetherLink.Client.csproj -c Release -r win-x64 -o $OutDir

Write-Output "==> Staging core DLL + wintun..."
Copy-Item -Force target/release/aetherlink_ffi.dll "$OutDir/aetherlink_core.dll"
if (Test-Path -LiteralPath ./wintun.dll) {
    Copy-Item -Force ./wintun.dll $OutDir
} else {
    Write-Warning "wintun.dll not found next to repo root; place it in $OutDir (v2rayN-style, see https://www.wintun.net/)."
}
if (-not (Test-Path -LiteralPath $Config)) {
    Copy-Item -Force configs/client.example.yaml $Config
}

try {
    Write-Output "==> Tunnel up with $Config (Ctrl+C brings it down, DNS/routes restored)..."
    & "$OutDir/AetherLink.Client.exe" $Config up
} finally {
    Write-Output "==> Restoring network/DNS (force_cleanup, idempotent)..."
    & "$OutDir/AetherLink.Client.exe" $Config cleanup
}
