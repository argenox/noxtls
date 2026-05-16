param(
    [string]$OutputZip = "",
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if([string]::IsNullOrWhiteSpace($OutputZip)) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputZip = Join-Path $repoRoot ("noxtls-package-{0}.zip" -f $timestamp)
}

if(-not [System.IO.Path]::IsPathRooted($OutputZip)) {
    $OutputZip = Join-Path $repoRoot $OutputZip
}

$requestedItems = @(
    "applications",
    "BUILDING.md",
    "CMAKELists.txt",
    "COPYING.md",
    "Doxyfile",
    "LICENSE.md",
    "noxtls_check_config.h",
    "nxotls_common.h",
    "noxtls_config.h",
    "noxtls-lib",
    "noxtls_version.h",
    "README.md",
    "scripts",
    "SECURITY.md",
    "ut",
    "utility"
)

# Fallbacks for known naming mismatches in the provided list.
$fallbackMap = @{
    "CMAKELists.txt" = "CMakeLists.txt"
    "nxotls_common.h" = "noxtls_common.h"
}

function Resolve-PathWithActualLeafCase {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue
    )

    $parent = Split-Path -Parent $PathValue
    $leaf = Split-Path -Leaf $PathValue
    if([string]::IsNullOrWhiteSpace($parent) -or [string]::IsNullOrWhiteSpace($leaf)) {
        return (Get-Item -LiteralPath $PathValue).FullName
    }

    $entry = Get-ChildItem -LiteralPath $parent | Where-Object { $_.Name -ieq $leaf } | Select-Object -First 1
    if($null -ne $entry) {
        return $entry.FullName
    }

    return (Get-Item -LiteralPath $PathValue).FullName
}

$resolvedPaths = New-Object System.Collections.Generic.List[string]
$missingItems = New-Object System.Collections.Generic.List[string]

foreach($item in $requestedItems) {
    $primary = Join-Path $repoRoot $item
    if(Test-Path -LiteralPath $primary) {
        $canonical = Resolve-PathWithActualLeafCase -PathValue $primary
        [void]$resolvedPaths.Add($canonical)
        continue
    }

    if($fallbackMap.ContainsKey($item)) {
        $fallback = Join-Path $repoRoot $fallbackMap[$item]
        if(Test-Path -LiteralPath $fallback) {
            $canonical = Resolve-PathWithActualLeafCase -PathValue $fallback
            [void]$resolvedPaths.Add($canonical)
            continue
        }
    }

    [void]$missingItems.Add($item)
}

if($missingItems.Count -gt 0) {
    Write-Error ("Cannot create zip. Missing items: {0}" -f ($missingItems -join ", "))
}

if((Test-Path -LiteralPath $OutputZip) -and -not $Force.IsPresent) {
    Write-Error ("Output zip already exists: {0}. Use -Force to overwrite." -f $OutputZip)
}

if(Test-Path -LiteralPath $OutputZip) {
    Remove-Item -LiteralPath $OutputZip -Force
}

Compress-Archive -Path $resolvedPaths.ToArray() -DestinationPath $OutputZip -CompressionLevel Optimal

Write-Host ("Created zip: {0}" -f $OutputZip)
Write-Host "Included items:"
foreach($path in $resolvedPaths) {
    $relative = $path
    $baseNorm = [System.IO.Path]::GetFullPath($repoRoot).TrimEnd('\', '/')
    $targetNorm = [System.IO.Path]::GetFullPath($path)
    if($targetNorm.StartsWith($baseNorm, [System.StringComparison]::OrdinalIgnoreCase)) {
        $relative = $targetNorm.Substring($baseNorm.Length).TrimStart('\', '/')
    }
    Write-Host (" - {0}" -f $relative)
}
