#!/usr/bin/env pwsh
# Android build contract (Phase 0 gate).
#
# TDD RED gate: on the current HEAD this fails because there is no Gradle
# wrapper, no root build file, no build script and no APK symbol contract.
# GREEN when `scripts/build_android.ps1` reproduces the APK from a clean clone.
#
# Checks:
#   1. required build files exist;
#   2. wrapper pins Gradle 8.10.2;
#   3. core + APK build (unless -SkipBuild);
#   4. APK contains all three ABI .so files;
#   5. every Kotlin `external fun` in AetherCore.kt has its JNI symbol.
[CmdletBinding()]
param(
    [switch]$SkipBuild
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$android = Join-Path $root "apps/android"
$app = Join-Path $android "app"
$apk = Join-Path $app "build/outputs/apk/debug/app-debug.apk"
$fail = 0

function Check($name, $cond) {
    if ($cond) { Write-Output "ok   $name" }
    else { Write-Output "FAIL $name"; $script:fail++ }
}

function Check-File($path, $name) {
    Check "$name ($path)" (Test-Path -LiteralPath $path)
}

Write-Output "== Android build contract =="

# 1. Build files.
Check-File (Join-Path $android "settings.gradle") "settings.gradle"
Check-File (Join-Path $android "build.gradle") "root build.gradle"
Check-File (Join-Path $android "gradlew") "gradlew"
Check-File (Join-Path $android "gradlew.bat") "gradlew.bat"
Check-File (Join-Path $android "gradle/wrapper/gradle-wrapper.properties") "wrapper properties"
Check-File (Join-Path $android "gradle/wrapper/gradle-wrapper.jar") "wrapper jar"
Check-File (Join-Path $root "scripts/build_android.ps1") "build_android.ps1"
Check-File (Join-Path $root "scripts/build_android.sh") "build_android.sh"
Check-File (Join-Path $app "build.gradle") "app/build.gradle"

# 2. Wrapper version.
$wrapper = Join-Path $android "gradle/wrapper/gradle-wrapper.properties"
if (Test-Path -LiteralPath $wrapper) {
    $props = Get-Content -LiteralPath $wrapper -Raw
    Check "wrapper pins Gradle 8.10.2" ($props -match "gradle-8\.10\.2-bin\.zip")
}

# 3. Build.
if (-not $SkipBuild) {
    Write-Output "-- building core + APK --"
    & (Join-Path $root "scripts/build_android.ps1")
    if ($LASTEXITCODE -ne 0) {
        Write-Output "FAIL build_android.ps1 exited $LASTEXITCODE"
        $fail++
    }
}

# 4. APK ABI payload.
if (Test-Path -LiteralPath $apk) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($apk)
    try {
        $entries = @($zip.Entries | ForEach-Object { $_.FullName })
    } finally {
        $zip.Dispose()
    }
    foreach ($abi in @("arm64-v8a", "armeabi-v7a", "x86_64")) {
        $entry = "lib/$abi/libaetherlink_core.so"
        Check "APK contains $entry" ($entries -contains $entry)
    }
} else {
    Check "APK exists ($apk)" $false
}

# 5. JNI symbol contract: Kotlin externals <-> .so symbols.
$coreKt = Join-Path $app "src/main/java/link/aether/client/AetherCore.kt"
$so = Join-Path $app "src/main/jniLibs/arm64-v8a/libaetherlink_core.so"
if ((Test-Path -LiteralPath $coreKt) -and (Test-Path -LiteralPath $so)) {
    $ndk = $env:ANDROID_NDK_HOME
    if (-not $ndk -and $env:ANDROID_HOME) { $ndk = Join-Path $env:ANDROID_HOME "ndk/28.2.13676358" }
    $nm = Join-Path $ndk "toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe"
    if (Test-Path -LiteralPath $nm) {
        $syms = & $nm -D --defined-only --format=posix $so 2>$null
        $text = Get-Content -LiteralPath $coreKt -Raw
        $externals = [regex]::Matches($text, "external\s+fun\s+(\w+)") |
            ForEach-Object { $_.Groups[1].Value }
        Check "AetherCore.kt declares externals" ($externals.Count -gt 0)
        foreach ($fn in $externals) {
            Check "JNI symbol $fn" ($syms -match "Java_link_aether_client_AetherCore_$fn")
        }
    } else {
        Check "llvm-nm available ($nm)" $false
    }
} else {
    Check "JNI contract inputs (AetherCore.kt + arm64 .so)" $false
}

if ($fail -gt 0) {
    Write-Output "$fail android build checks failed"
    exit 1
}
Write-Output "all android build checks passed"
