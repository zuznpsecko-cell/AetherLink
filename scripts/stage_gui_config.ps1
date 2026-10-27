# Stage client.local.yaml into the GUI output directory without wiping saved
# endpoint profiles. The app writes user profiles into this file; a rebuild
# must not replace it silently.
#
#   .\scripts\stage_gui_config.ps1 -Source configs/client.example.yaml -OutDir dist/win-gui
#   .\scripts\stage_gui_config.ps1 -Source configs/client.example.yaml -OutDir dist/win-gui -Reset
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$OutDir,
    [switch]$Reset
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Source)) {
    throw "config source not found: $Source"
}

if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}

$target = Join-Path $OutDir "client.local.yaml"

if ((Test-Path -LiteralPath $target) -and -not $Reset) {
    Write-Output "kept existing $target (saved profiles preserved; use -Reset to replace)"
    exit 0
}

if ($Reset -and (Test-Path -LiteralPath $target)) {
    $backup = "$target.bak-" + (Get-Date -Format "yyyyMMdd-HHmmss")
    Copy-Item -LiteralPath $target -Destination $backup -Force
    Write-Output "backed up $target to $backup"
}

Copy-Item -LiteralPath $Source -Destination $target -Force
Write-Output "seeded $target from $Source"
