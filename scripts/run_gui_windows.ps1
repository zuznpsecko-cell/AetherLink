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

function Invoke-Native([string]$Exe, [string]$Arguments, [string]$What) {
    # NOTE: `& $Exe @Args` splatting misfires on PS 5.1; Start-Process
    # with a log file judges by exit code instead.
    $log = [System.IO.Path]::GetTempFileName() + ".log"
    $p = Start-Process -FilePath $Exe -ArgumentList $Arguments -Wait -NoNewWindow -PassThru `
        -RedirectStandardOutput $log -RedirectStandardError ($log + ".err")
    if ($p.ExitCode -ne 0) {
        Get-Content -LiteralPath $log -ErrorAction SilentlyContinue | Select-Object -Last 10
        Get-Content -LiteralPath ($log + ".err") -ErrorAction SilentlyContinue | Select-Object -Last 10
        throw "$What failed with exit $($p.ExitCode)"
    }
    Remove-Item -LiteralPath $log, ($log + ".err") -ErrorAction SilentlyContinue
}

Write-Output "==> Building Rust core (aetherlink-ffi cdylib, release)..."
Invoke-Native "cargo" "build --release -p aetherlink-ffi" "cargo build"

Write-Output "==> Publishing Avalonia GUI host (win-x64, self-contained)..."
Invoke-Native "dotnet" "publish dotnet/AetherLink.Gui/AetherLink.Gui.csproj -c Release -r win-x64 -o $OutDir" "dotnet publish"

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
