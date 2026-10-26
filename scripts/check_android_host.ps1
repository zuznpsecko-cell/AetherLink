#!/usr/bin/env pwsh
# Android thin-host contract (final shape, TDD RED first).
#
# This is the RED gate for the Kotlin host work: it fails on the current
# skeleton and turns GREEN at G3 (full tunnel) / G4 (split). It is separate
# from `check_thin_hosts.ps1` so the desktop gate stays green while the
# Android host is being rebuilt.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root "apps/android/app/src/main/java/link/aether/client"
$manifest = Join-Path $root "apps/android/app/src/main/AndroidManifest.xml"
$fail = 0

function Check($name, $cond) {
    if ($cond) { Write-Output "ok   $name" }
    else { Write-Output "FAIL $name"; $script:fail++ }
}
function Code-Text($path) {
    if (-not (Test-Path -LiteralPath $path)) { return "" }
    ((Get-Content -LiteralPath $path) | Where-Object { $_ -notmatch '^\s*//' }) -join "`n"
}
function Has-Text($path, $pattern) {
    (Code-Text $path) -match $pattern
}
function No-Text($path, $pattern) {
    -not (Has-Text $path $pattern)
}

Write-Output "== Android host contract =="

# --- required Kotlin files (final shape) ---
$files = @(
    "MainActivity.kt",
    "AetherVpnService.kt",
    "AetherCore.kt",
    "CoreApi.kt",
    "ConfigStore.kt",
    "ConfigCodec.kt",
    "ServiceState.kt",
    "VpnBuilderSpec.kt",
    "ConnectFlow.kt",
    "VpnFacade.kt",
    "AndroidVpnFacade.kt",
    "AppPickerActivity.kt",
    "AppPickerModel.kt"
)
foreach ($f in $files) {
    Check "exists $f" (Test-Path -LiteralPath (Join-Path $src $f))
}

$main = Join-Path $src "MainActivity.kt"
$service = Join-Path $src "AetherVpnService.kt"
$core = Join-Path $src "AetherCore.kt"
$picker = Join-Path $src "AppPickerActivity.kt"

# --- manifest: launcher + VPN service + FGS specialUse ---
$m = if (Test-Path -LiteralPath $manifest) { Get-Content -LiteralPath $manifest -Raw } else { "" }
Check "manifest has LAUNCHER activity" ($m -match 'android\.intent\.action\.MAIN' -and $m -match 'android\.intent\.category\.LAUNCHER')
Check "manifest declares VpnService action" ($m -match 'android\.net\.VpnService')
Check "manifest requires BIND_VPN_SERVICE" ($m -match 'BIND_VPN_SERVICE')
Check "manifest service exported=false" ($m -match 'android:exported="false"')
Check "manifest FGS specialUse permission" ($m -match 'FOREGROUND_SERVICE_SPECIAL_USE')
Check "manifest FGS specialUse type" ($m -match 'foregroundServiceType="specialUse"')
Check "manifest FGS subtype property" ($m -match 'PROPERTY_SPECIAL_USE_FGS_SUBTYPE')
Check "manifest POST_NOTIFICATIONS" ($m -match 'POST_NOTIFICATIONS')

# --- thin host: no crypto / TLS / frame parsing in Kotlin ---
$ktFiles = @(Get-ChildItem -LiteralPath $src -Filter *.kt -ErrorAction SilentlyContinue)
foreach ($f in $ktFiles) {
    Check "no javax.crypto in $($f.Name)" (No-Text $f.FullName 'javax\.crypto')
    Check "no TLS stack in $($f.Name)" (No-Text $f.FullName 'SSLContext|TrustManager|KeyManager|Cipher\.getInstance')
}

# --- lifecycle shape ---
Check "MainActivity is ComponentActivity" (Has-Text $main ':\s*ComponentActivity')
Check "prepare() is called" ((Has-Text $main 'VpnService\.prepare\(') -or (Has-Text (Join-Path $src 'ConnectFlow.kt') 'VpnService\.prepare\('))
Check "service creates core handle" (Has-Text $service 'clientCreate\(')
Check "service asks for plan" (Has-Text $service 'clientPlan\(')
Check "service connects" (Has-Text $service 'clientConnect\(')
Check "service attaches tun fd" (Has-Text $service 'clientAttachTun\(')
Check "service detaches fd" (Has-Text $service 'detachFd\(\)')
Check "service does not use staging setTunFd" (No-Text $service 'setTunFd\(')
Check "service has real handle (no 0L stub)" (No-Text $service 'handle\(\)\s*:\s*Long\s*=\s*0L')
Check "service dispatches off main thread" ((Has-Text $service 'Executor|executor|Thread\('))
Check "core exposes protectFd" (Has-Text $core 'protectFd')
Check "core exposes new JNI contract" (
    (Has-Text $core 'clientAttachTun') -and
    (Has-Text $core 'clientStatus') -and
    (Has-Text $core 'clientFree')
)
Check "no PSK in Intent extras" (No-Text $service 'putExtra\([^)]*psk')

# --- split UI: one app picker with checkboxes ---
Check "AppPicker has checkboxes" (Has-Text $picker 'CheckBox')
Check "AppPicker has search" (Has-Text $picker 'EditText|SearchView')

if ($fail -gt 0) {
    Write-Output "$fail android host checks failed"
    exit 1
}
Write-Output "all android host checks passed"
