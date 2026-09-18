# Quickstart: AetherLink server on Windows.
# One command from repo root: .\scripts\run_server_windows.ps1 [-Config <path>]
# Builds the Rust core (cdylib), publishes the thin .NET host self-contained,
# stages config + static fallback dir, then runs. Ctrl+C stops (host disposes).
[CmdletBinding()]
param(
    [string]$Config = "configs/server.example.yaml",
    [string]$OutDir = "dist/win-server"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root

Write-Output "==> Building Rust core (aetherlink-ffi cdylib, release)..."
cargo build --release -p aetherlink-ffi

Write-Output "==> Publishing thin .NET server host (win-x64, self-contained)..."
dotnet publish dotnet/AetherLink.Server/AetherLink.Server.csproj -c Release -r win-x64 -o $OutDir

Write-Output "==> Staging core DLL + config..."
Copy-Item -Force target/release/aetherlink_ffi.dll "$OutDir/aetherlink_core.dll"
if (-not (Test-Path -LiteralPath $Config)) {
    Copy-Item -Force configs/server.example.yaml $Config
}
$fallback = Join-Path $OutDir "fallback"
New-Item -ItemType Directory -Force -Path $fallback | Out-Null
if (-not (Test-Path -LiteralPath (Join-Path $fallback "index.html"))) {
    Set-Content -LiteralPath (Join-Path $fallback "index.html") "<html><body>AetherLink</body></html>"
}
if (-not ((Test-Path -LiteralPath "./cert.pem") -and (Test-Path -LiteralPath "./key.pem"))) {
    Write-Warning "TLS cert/key not found (./cert.pem, ./key.pem). Generate self-signed for smoke, real CA for production."
}

Write-Output "==> Running server with $Config (Ctrl+C to stop)..."
& "$OutDir/AetherLink.Server.exe" $Config
