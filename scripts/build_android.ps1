#!/usr/bin/env pwsh
# Reproducible Android build: Rust core (.so for 3 ABIs) + debug APK.
# Requires: Rust targets for Android, cargo-ndk, Android SDK/NDK, Java 17+ (21 recommended).
[CmdletBinding()]
param(
    [ValidateSet("debug", "release")]
    [string]$Variant = "debug",
    [switch]$SkipGradle
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$android = Join-Path $root "apps/android"
$jniLibs = Join-Path $android "app/src/main/jniLibs"

function Fail($msg) { throw "build_android: $msg" }

# --- Java: Gradle 8.10 / AGP 8.6 want 17-23; prefer a 21 JDK if JAVA_HOME is newer ---
function Get-JavaMajor($javaDir) {
    $exe = Join-Path $javaDir "bin/java.exe"
    if (-not (Test-Path -LiteralPath $exe)) { return 0 }
    # cmd /c keeps `java -version` stderr out of PowerShell's error stream.
    $line = (cmd /c "`"$exe`" -version 2>&1" | Select-Object -First 1)
    if ($line -match '"(\d+)') { return [int]$Matches[1] }
    return 0
}
$candidates = @(
    $env:JAVA_HOME,
    "C:/Program Files/Android/openjdk/jdk-21.0.8",
    "C:/Program Files/Android/openjdk",
    "F:/Program Files/Android/jbr"
) | Where-Object { $_ -and (Test-Path -LiteralPath (Join-Path $_ "bin/java.exe")) }
$javaHome = $null
foreach ($c in $candidates) {
    $m = Get-JavaMajor $c
    if ($m -ge 17 -and $m -le 23) { $javaHome = $c; break }
}
if (-not $javaHome) {
    foreach ($c in $candidates) { if ((Get-JavaMajor $c) -ge 17) { $javaHome = $c; break } }
}
if (-not $javaHome) { Fail "JDK 17+ is required (set JAVA_HOME)" }
$env:JAVA_HOME = $javaHome
$env:Path = (Join-Path $javaHome "bin") + ";" + $env:Path
$major = Get-JavaMajor $javaHome
if ($major -gt 23) { Write-Warning "Gradle 8.10 / AGP 8.6 are not tested on Java $major; install JDK 21 for reproducible builds" }
Write-Host "java $major ($javaHome)"

# --- Android SDK/NDK ---
if (-not $env:ANDROID_HOME) {
    if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_HOME = $env:ANDROID_SDK_ROOT }
    elseif (Test-Path "F:/Android/Sdk") { $env:ANDROID_HOME = "F:/Android/Sdk" }
}
if (-not $env:ANDROID_HOME -or -not (Test-Path -LiteralPath $env:ANDROID_HOME)) {
    Fail "ANDROID_HOME is required"
}
if (-not $env:ANDROID_NDK_HOME) {
    $ndkRoot = Join-Path $env:ANDROID_HOME "ndk"
    $ndk = Get-ChildItem -LiteralPath $ndkRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($ndk) { $env:ANDROID_NDK_HOME = $ndk.FullName }
}
if (-not $env:ANDROID_NDK_HOME -or -not (Test-Path -LiteralPath $env:ANDROID_NDK_HOME)) {
    Fail "ANDROID_NDK_HOME (or SDK/ndk/<version>) is required"
}
Write-Host "ANDROID_HOME=$env:ANDROID_HOME"
Write-Host "ANDROID_NDK_HOME=$env:ANDROID_NDK_HOME"

# Native tools write progress to stderr; route everything through `cmd /c` so
# PowerShell does not turn that into a NativeCommandError with -ErrorAction Stop.
# Output goes to a log file: a piped child that spawns a daemon (Gradle) would
# otherwise keep the pipe open and hang the script after the build is done.
$script:buildLog = Join-Path ([System.IO.Path]::GetTempPath()) "aetherlink-build-android.log"
function Invoke-Native($workDir, $commandLine, [switch]$Quiet) {
    Push-Location $workDir
    try {
        & cmd /c "$commandLine > `"$script:buildLog`" 2>&1"
        $code = $LASTEXITCODE
        if (-not $Quiet -and (Test-Path -LiteralPath $script:buildLog)) {
            Get-Content -LiteralPath $script:buildLog | Select-Object -Last 25 | ForEach-Object { Write-Host $_ }
        }
        return $code
    } finally {
        Pop-Location
    }
}

# --- cargo-ndk + Rust targets ---
$code = Invoke-Native $root "cargo ndk --version" -Quiet
if ($code -ne 0) { Fail "cargo-ndk is not installed (cargo install cargo-ndk)" }
$installed = & rustup target list --installed
foreach ($target in @("aarch64-linux-android", "armv7-linux-androideabi", "x86_64-linux-android")) {
    if (-not ($installed -contains $target)) { Fail "rustup target add $target" }
}

# --- Rust core for all ABIs ---
# The crate lib is `aetherlink_ffi`; hosts load it as `aetherlink_core`
# (same staging rule as the .NET hosts: ffi.dll -> core.dll).
Write-Host "building aetherlink-ffi for arm64-v8a, armeabi-v7a, x86_64"
$abis = @("arm64-v8a", "armeabi-v7a", "x86_64")
foreach ($abi in $abis) {
    $dir = Join-Path $jniLibs $abi
    if (Test-Path -LiteralPath $dir) { Get-ChildItem -LiteralPath $dir -Filter *.so | Remove-Item -Force }
}
$ndkArgs = "cargo ndk --platform 26 -t arm64-v8a -t armeabi-v7a -t x86_64 -o `"$jniLibs`" build --release -p aetherlink-ffi"
$code = Invoke-Native $root $ndkArgs
if ($code -ne 0) { Fail "cargo ndk exited $code" }
foreach ($abi in $abis) {
    $built = Join-Path $jniLibs "$abi/libaetherlink_ffi.so"
    $so = Join-Path $jniLibs "$abi/libaetherlink_core.so"
    if (-not (Test-Path -LiteralPath $built)) { Fail "missing $built" }
    Move-Item -LiteralPath $built -Destination $so -Force
    Write-Host "  $abi -> $so"
}

if ($SkipGradle) {
    Write-Host "APK build skipped (-SkipGradle)"
    exit 0
}

# --- APK ---
$task = "assemble" + (Get-Culture).TextInfo.ToTitleCase($Variant)
$code = Invoke-Native $android "gradlew.bat $task --console=plain"
if ($code -ne 0) { Fail "gradlew $task exited $code" }

$apk = Join-Path $android "app/build/outputs/apk/$Variant/app-$Variant.apk"
if (-not (Test-Path -LiteralPath $apk)) { Fail "APK not found: $apk" }
Write-Host ""
Write-Host "APK: $apk"

