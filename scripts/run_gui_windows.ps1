# Quickstart: AetherLink GUI client on Windows. Run ELEVATED (admin) to test:
#   .\scripts\run_gui_windows.ps1 [-Config <path>]
# Builds core, publishes the Avalonia GUI host (win-x64, self-contained),
# stages core DLL + wintun.dll side-by-side. The app itself prompts for
# admin at startup (requireAdministrator manifest).
[CmdletBinding()]
param(
    [string]$Config = "configs/client.example.yaml",
    [string]$OutDir = "dist/win-gui"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root

Write-Output "==> Building Rust core (aetherlink-ffi cdylib, release)..."
cargo build --release -p aetherlink-ffi

Write-Output "==> Publishing Avalonia GUI host (win-x64, self-contained)..."
dotnet publish dotnet/AetherLink.Gui/AetherLink.Gui.csproj -c Release -r win-x64 -o $OutDir

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
Copy-Item -Force $Config "$OutDir/client.local.yaml"

Write-Output "==> Staged in $OutDir (run AetherLink.Gui.exe elevated)."
