#!/usr/bin/env pwsh
# Windows GUI endpoint-profile contract (TDD gate).
# Fails while the multi-endpoint UI, config round-trip or thin-host rules
# regress. Complements check_thin_hosts.ps1 (which now also guards the GUI).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$fail = 0

function Check($name, $cond) {
    if ($cond) { Write-Output "ok   $name" } else { Write-Output "FAIL $name"; $script:fail++ }
}

function Code-Text($path) {
    ((Get-Content $path) | Where-Object { $_ -notmatch '^\s*//' }) -join "`n"
}

function Has-Text($path, $pattern) {
    (Code-Text $path) -match $pattern
}

$gui = "$root/dotnet/AetherLink.Gui"
$guiCsproj = "$gui/AetherLink.Gui.csproj"
$configService = "$gui/Services/ConfigService.cs"
$mainVm = "$gui/ViewModels/MainViewModel.cs"
$window = "$gui/Views/MainWindow.axaml"
$example = "$root/configs/client.example.yaml"
$testsCsproj = "$root/dotnet/AetherLink.Gui.Tests/AetherLink.Gui.Tests.csproj"

foreach ($f in @($guiCsproj, $configService, $mainVm, $window, $example, $testsCsproj)) {
    Check "exists $f" (Test-Path -LiteralPath $f)
}
if ($fail -gt 0) { Write-Output "$fail checks failed"; exit 1 }

# --- config contract ---
Check "config writes endpoints" (Has-Text $configService '"endpoints"')
Check "config writes active_endpoint" (Has-Text $configService '"active_endpoint"')
Check "config reads endpoints" (Has-Text $configService 'TryGetValue\("endpoints"')
Check "config writes legacy mirror" (Has-Text $configService '"server_addr"')

# --- view model contract ---
Check "vm owns endpoint book" (Has-Text $mainVm "EndpointBook")
Check "vm switches profiles" (Has-Text $mainVm "EndpointSwitcher")
Check "vm exposes SelectedEndpoint" (Has-Text $mainVm "SelectedEndpoint")
Check "vm saves on selection" (Has-Text $mainVm "OnSelectedEndpointChanged")

# --- ui contract ---
Check "ui binds endpoint list" (Has-Text $window 'ItemsSource="\{Binding Endpoints\}"')
Check "ui binds selected endpoint" (Has-Text $window 'SelectedItem="\{Binding SelectedEndpoint')
foreach ($cmd in @("AddEndpointCommand", "DuplicateEndpointCommand", "DeleteEndpointCommand")) {
    Check "ui has $cmd" (Has-Text $window $cmd)
}
Check "ui shows endpoint address" (Has-Text $window "SelectedEndpoint.ServerAddr")

# --- thin host / no skeletons ---
$sources = @(Get-ChildItem $gui -Recurse -Filter *.cs |
    Where-Object { $_.FullName -notmatch '\\(bin|obj)\\' })
$crypto = @($sources | Where-Object { (Code-Text $_.FullName) -match "(SslStream|ChaCha|HMAC|AesGcm)" })
Check "gui has no crypto stack" ($crypto.Count -eq 0)

$stubs = @($sources | Where-Object { (Code-Text $_.FullName) -match "NotImplementedException" })
Check "gui has no NotImplementedException stubs" ($stubs.Count -eq 0)

$pskLogs = @($sources | Where-Object { (Code-Text $_.FullName) -match "GuiLog\.(Info|Warn|Error)\(.*[Pp][Ss][Kk]" })
Check "gui never logs PSK" ($pskLogs.Count -eq 0)

# --- example config + tests ---
Check "example config documents endpoints" (Has-Text $example "(?m)^\s*endpoints:")
Check "example config documents active endpoint" (Has-Text $example "(?m)^\s*active_endpoint:")
Check "tests project references gui" (Has-Text $testsCsproj "AetherLink\.Gui")
Check "gui exposes internals to tests" (Has-Text $guiCsproj "InternalsVisibleTo")

if ($fail -gt 0) { Write-Output "$fail checks failed"; exit 1 }
Write-Output "all gui endpoint checks passed"
