#!/usr/bin/env pwsh
# Thin-host contract checks (TDD RED first, then GREEN).
# .NET hosts and Android UI must be THIN: config + service + FFI calls only.
# A second protocol/crypto stack in C#/Kotlin is FORBIDDEN (AGENT_INSTRUCTIONS §1.1, DoD #1).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$fail = 0
function Check($name, $cond) {
    if ($cond) { Write-Output "ok   $name" } else { Write-Output "FAIL $name"; $script:fail++ }
}
function Code-Text($path) {
    # Code without // line comments (so doc comments can't trip negative checks).
    ((Get-Content $path) | Where-Object { $_ -notmatch '^\s*//' }) -join "`n"
}
function Has-Text($path, $pattern) {
    (Code-Text $path) -match $pattern
}
function No-Text($path, $pattern) {
    -not (Has-Text $path $pattern)
}

# --- required files ---
$serverCsproj = "$root/dotnet/AetherLink.Server/AetherLink.Server.csproj"
$serverProg  = "$root/dotnet/AetherLink.Server/Program.cs"
$clientCsproj = "$root/dotnet/AetherLink.Client/AetherLink.Client.csproj"
$clientProg  = "$root/dotnet/AetherLink.Client/Program.cs"
$vpnService  = "$root/apps/android/app/src/main/java/link/aether/client/AetherVpnService.kt"
$jniBridge   = "$root/apps/android/app/src/main/java/link/aether/client/AetherCore.kt"
$manifest    = "$root/apps/android/app/src/main/AndroidManifest.xml"
$appGradle   = "$root/apps/android/app/build.gradle"
$linDeploy   = "$root/deploy/linux/install.sh"
$linUninstall = "$root/deploy/linux/uninstall.sh"
$winDeploy   = "$root/deploy/windows/install.ps1"
$winUninstall = "$root/deploy/windows/uninstall.ps1"
$linUnit     = "$root/deploy/linux/aetherlink-server.service"
$deployDoc   = "$root/docs/DEPLOY_UBUNTU.md"
$clientCfg   = "$root/configs/client.example.yaml"
$serverCfg   = "$root/configs/server.example.yaml"
$settingsGradle = "$root/apps/android/settings.gradle"
$jniLibs     = "$root/apps/android/app/src/main/jniLibs"
foreach ($f in @($serverCsproj, $serverProg, $clientCsproj, $clientProg, $vpnService, $jniBridge, $manifest, $appGradle, $settingsGradle, $linDeploy, $linUninstall, $winDeploy, $winUninstall, $linUnit, $deployDoc, $clientCfg, $serverCfg)) {
    Check "exists $f" (Test-Path -LiteralPath $f)
}
if ($fail -gt 0) { Write-Output "$fail checks failed"; exit 1 }

# --- .NET Server: FFI in, no data-plane of its own ---
Check "server imports aether_server_start" (Has-Text $serverProg "aether_server_start")
Check "server imports aether_server_stop" (Has-Text $serverProg "aether_server_stop")
Check "server has no SslStream" (No-Text $serverProg "SslStream")
Check "server has no ChaCha/HMAC" (No-Text $serverProg "(ChaCha|HMAC|AesGcm)")
Check "server self-contained publish" (Has-Text $serverCsproj "SelfContained")

# --- .NET Client: FFI up/down/status/cleanup, Wintun path note ---
Check "client imports aether_client_up" (Has-Text $clientProg "aether_client_up")
Check "client imports aether_client_down" (Has-Text $clientProg "aether_client_down")
Check "client imports force_cleanup" (Has-Text $clientProg "force_cleanup")
Check "client has no SslStream" (No-Text $clientProg "SslStream")
Check "client has no ChaCha/HMAC" (No-Text $clientProg "(ChaCha|HMAC|AesGcm)")
Check "client self-contained publish" (Has-Text $clientCsproj "SelfContained")

# --- Android: VpnService fd -> core, split default all, no crypto in Kotlin ---
Check "vpn establishes Builder" (Has-Text $vpnService "Builder")
Check "vpn passes tun fd to core" (Has-Text $vpnService "setTunFd|SetTunFd|tunFd")
Check "split default all" (Has-Text $vpnService "MODE_ALL|mode.*all")
Check "kotlin has no javax.crypto" (No-Text $vpnService "javax\.crypto")
Check "kotlin has no javax.crypto (bridge)" (No-Text $jniBridge "javax\.crypto")
Check "bridge loads aetherlink_core" (Has-Text $jniBridge "aetherlink_core")
Check "manifest declares VpnService" (Has-Text $manifest "android.net.VpnService")
Check "manifest requires BIND_VPN_SERVICE" (Has-Text $manifest "BIND_VPN_SERVICE")
Check "gradle pins minSdk 26" (Has-Text $appGradle "minSdk 26")
Check "gradle pins targetSdk 35" (Has-Text $appGradle "targetSdk 35")
Check "settings includes app module" (Has-Text $settingsGradle "include\(':app'\)")
foreach ($abi in @("arm64-v8a", "armeabi-v7a", "x86_64")) {
    Check "jniLibs $abi/libaetherlink_core.so staged" (Test-Path -LiteralPath "$jniLibs/$abi/libaetherlink_core.so")
}
$sdkRoot = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "F:/Android/Sdk" }
$nm = "$sdkRoot/ndk/28.2.13676358/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe"
if (Test-Path -LiteralPath $nm) {
    $syms = & $nm -D --defined-only --format=posix "$jniLibs/arm64-v8a/libaetherlink_core.so" 2>$null
    foreach ($sym in @("clientCreate", "clientUp", "clientDown", "setTunFd", "setSplitConfig", "forceCleanup")) {
        Check "jni symbol Java_link_aether_client_AetherCore_$sym" ($syms -match "Java_link_aether_client_AetherCore_$sym")
    }
} else {
    Write-Output "skip jni symbol checks (llvm-nm not found)"
}

# --- deploy scripts mention lifecycle + DNS restore ---
Check "linux deploy restores DNS" (Has-Text $linDeploy "(resolv|systemd-resolved|DNS)")
Check "linux deploy cleanup" (Has-Text $linDeploy "(cleanup|force_cleanup|state\.json)")
Check "linux deploy installs unit" (Has-Text $linDeploy "aetherlink-server\.service")
Check "linux deploy copies full publish dir" (Has-Text $linDeploy "dist/ubuntu-server/\.")
Check "linux uninstall removes unit" (Has-Text $linUninstall "aetherlink-server\.service")
Check "windows deploy mentions wintun" (Has-Text $winDeploy "(wintun|Wintun)")
Check "windows deploy restores DNS" (Has-Text $winDeploy "(DNS|NRPT)")
Check "windows uninstall removes state" (Has-Text $winUninstall "ProgramData")
Check "unit runs published server" (Has-Text $linUnit "AetherLink\.Server")
Check "unit reads server.yaml" (Has-Text $linUnit "server\.yaml")
Check "deploy doc covers renewal" (Has-Text $deployDoc "(deploy-hook|renew)")

# --- example configs carry §8 fields ---
Check "client cfg server_addr" (Has-Text $clientCfg "server_addr")
Check "client cfg dns_mode tunnel" (Has-Text $clientCfg "dns_mode:\s*tunnel")
Check "server cfg dns_upstream" (Has-Text $serverCfg "dns_upstream")
Check "server cfg static root" (Has-Text $serverCfg "local_static_root")

if ($fail -gt 0) { Write-Output "$fail checks failed"; exit 1 }
Write-Output "all thin-host checks passed"
