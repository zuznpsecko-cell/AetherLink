<#
.SYNOPSIS
Fetch the category-ads-all blocklist (flat suffix text) for the server.

Downloads the curated ads/tracker list, keeps comment/blank lines out,
writes one suffix per line (leading dot = suffix, same file the server
reads via `blocked_domains_file`). Re-run weekly/monthly to refresh.

Upstream: https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/category-ads-all.txt
(v2fly/domain-list-community `category-ads-all`, neutral global source:
https://github.com/v2fly/domain-list-community/tree/master/data)

Usage (repo root):
  .\scripts\fetch-blocklist.ps1 [-Out assets/blocklist-ads.txt]
#>
[CmdletBinding()]
param(
    [string]$Out = "assets/blocklist-ads.txt",
    [string]$Url = "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/category-ads-all.txt"
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $root $Out
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null

Write-Host "Fetching $Url ..." -ForegroundColor Cyan
$raw = Invoke-WebRequest -Uri $Url -UseBasicParsing | Select-Object -ExpandProperty Content
$lines = $raw -split "`n" | ForEach-Object { $_.Trim() } | Where-Object {
    $_ -ne '' -and -not $_.StartsWith('#') -and -not $_.StartsWith('!')
}
# Normalize: lowercase, strip clash rule prefixes if any (DOMAIN-, DOMAIN-SUFFIX-).
$clean = $lines | ForEach-Object {
    $l = $_.ToLower()
    if ($l.StartsWith('domain-suffix,')) { $l.Substring(14).Split(',')[0].Trim() }
    elseif ($l.StartsWith('domain,')) { $l.Substring(7).Split(',')[0].Trim() }
    else { $l }
} | Where-Object { $_ -ne '' } | Sort-Object -Unique
Set-Content -Path $dest -Value $clean -Encoding utf8NoBOM
$n = ($clean | Measure-Object).Count
Write-Host "Wrote $n suffixes to $dest" -ForegroundColor Green
Write-Host "Point the server at it: blocked_domains_file: `"$Out`"" -ForegroundColor DarkGray
