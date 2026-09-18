#!/usr/bin/env pwsh
# Quickstart contract checks (TDD RED first, then GREEN).
# scripts/ must let a user go from zero to running server/client with one command
# on Windows (PowerShell) and Ubuntu (bash): build core -> publish hosts ->
# stage configs -> run, with safe teardown (routes/DNS restored).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$fail = 0
function Check($name, $cond) {
    if ($cond) { Write-Output "ok   $name" } else { Write-Output "FAIL $name"; $script:fail++ }
}
function Has-Text($path, $pattern) {
    ((Get-Content $path) -join "`n") -match $pattern
}
function No-Text($path, $pattern) {
    -not (Has-Text $path $pattern)
}

$winServer = "$root/scripts/run_server_windows.ps1"
$winClient = "$root/scripts/run_client_windows.ps1"
$ubuServer = "$root/scripts/run_server_ubuntu.sh"
$ubuClient = "$root/scripts/run_client_ubuntu.sh"
$provision = "$root/scripts/provision_cert_ubuntu.sh"
foreach ($f in @($winServer, $winClient, $ubuServer, $ubuClient, $provision)) {
    Check "exists $f" (Test-Path -LiteralPath $f)
}
if ($fail -gt 0) { Write-Output "$fail checks failed"; exit 1 }

# --- windows: build core, publish self-contained, stage, run ---
Check "win-server builds ffi cdylib" (Has-Text $winServer "cargo build.*aetherlink-ffi")
Check "win-server publishes host" (Has-Text $winServer "dotnet publish.*AetherLink\.Server")
Check "win-server runs server yaml" (Has-Text $winServer "server\.example\.yaml|server\.yaml")
Check "win-client builds ffi cdylib" (Has-Text $winClient "cargo build.*aetherlink-ffi")
Check "win-client publishes host" (Has-Text $winClient "dotnet publish.*AetherLink\.Client")
Check "win-client ups the tunnel" (Has-Text $winClient "up\b")
Check "win-client restores on exit" (Has-Text $winClient "(cleanup|down)")
Check "win-client notes wintun" (Has-Text $winClient "(wintun|Wintun)")
Check "win-client needs admin" (Has-Text $winClient "(admin|Admin|elevat)")

# --- ubuntu: same flow via bash + sudo ---
Check "ubu-server builds ffi cdylib" (Has-Text $ubuServer "cargo build.*aetherlink-ffi")
Check "ubu-server publishes host" (Has-Text $ubuServer "dotnet publish.*AetherLink\.Server")
Check "ubu-server runs server yaml" (Has-Text $ubuServer "server\.example\.yaml|server\.yaml")
Check "ubu-client builds ffi cdylib" (Has-Text $ubuClient "cargo build.*aetherlink-ffi")
Check "ubu-client publishes host" (Has-Text $ubuClient "dotnet publish.*AetherLink\.Client")
Check "ubu-client ups with sudo" (Has-Text $ubuClient "sudo")
Check "ubu-client traps teardown" (Has-Text $ubuClient "trap")
Check "ubu-client restores on exit" (Has-Text $ubuClient "(cleanup|down)")

Check "ubu-server resolves TLS_CERT/TLS_KEY" (Has-Text $ubuServer "TLS_CERT.*TLS_KEY|TLS_KEY.*TLS_CERT")
Check "provision installs certbot plugin" (Has-Text $provision "python3-certbot-dns-cloudflare")
Check "provision uses dns-01 via cloudflare" (Has-Text $provision "dns-cloudflare")
Check "provision targets selmedia wildcard" (Has-Text $provision "selmedia\.ru")
Check "bundle script exists" (Test-Path -LiteralPath "$root/scripts/make_bundle.sh")
Check "bundle packs dist" (Has-Text "$root/scripts/make_bundle.sh" "dist/ubuntu-server")

$remoteInstall = "$root/deploy/linux/install-remote.sh"
Check "remote installer exists" (Test-Path -LiteralPath $remoteInstall)
Check "remote installs rustup" (Has-Text $remoteInstall "sh\.rustup\.rs|rustup")
Check "remote installs dotnet" (Has-Text $remoteInstall "dotnet-sdk")
Check "remote clones repo" (Has-Text $remoteInstall "git clone")
Check "remote generates PSK" (Has-Text $remoteInstall "openssl rand")
Check "remote self-signed fallback" (Has-Text $remoteInstall "req -x509")
Check "remote enables service" (Has-Text $remoteInstall "systemctl enable")
Check "remote opens firewall" (Has-Text $remoteInstall "ufw allow 443")
Check "remote prints client config" (Has-Text $remoteInstall "server_addr")
Check "remote takes DOMAIN param" (Has-Text $remoteInstall "DOMAIN=")
Check "remote has Cloudflare branch" (Has-Text $remoteInstall "CLOUDFLARE_API_TOKEN")
Check "remote has no hardcoded domain" (No-Text $remoteInstall "selmedia\.ru")
Check "remote prompts interactively" (Has-Text $remoteInstall "read -rp")
Check "remote reads token silently" (Has-Text $remoteInstall "read -rsp")
Check "remote has --yes escape hatch" (Has-Text $remoteInstall "--yes")

if ($fail -gt 0) { Write-Output "$fail checks failed"; exit 1 }
Write-Output "all quickstart checks passed"
