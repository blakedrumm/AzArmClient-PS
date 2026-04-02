#Requires -Version 5.1
<#
.SYNOPSIS
    Maintainer build script – bundles pinned Az modules and generates the
    integrity manifest for AzArmClient-PS.

.DESCRIPTION
    This script is intended for maintainers / CI pipelines, not for end users.

    It performs the following steps:

    1. Saves the pinned versions of the required Az modules into
       PSModuleCache\ (PowerShellGet / Save-Module).
    2. Computes SHA-256 hashes for all *.psm1 files under Modules\.
    3. Writes modules.sha256 (the integrity manifest consumed by AzArmClient.ps1).
    4. Optionally creates a zip archive under dist\ for distribution.

    ─── Pinned module versions ─────────────────────────────────────────────────
    Module          Version   Purpose
    ─────────────────────────────────────────────────────────────────────────────
    Az.Accounts     2.15.1    Interactive auth / Get-AzAccessToken
    ────────────────────────────────────────────────────────────────────────────
    Update $script:PinnedModules below when you need to upgrade a dependency.

.PARAMETER OutputDir
    Destination directory for the distribution zip (default: .\dist).

.PARAMETER ModuleCacheDir
    Directory where Az modules are saved (default: .\PSModuleCache).

.PARAMETER CreateZip
    When $true (default), produces a zip archive in OutputDir.

.PARAMETER SkipModuleDownload
    Skip the Save-Module step; useful when PSModuleCache already contains the
    correct versions.

.EXAMPLE
    # Full build
    .\Build-AzArmClient.ps1

.EXAMPLE
    # Regenerate manifest only (no download, no zip)
    .\Build-AzArmClient.ps1 -SkipModuleDownload -CreateZip:$false

.NOTES
    Author  : Blake Drumm
    Project : https://github.com/blakedrumm/AzArmClient-PS
    License : MIT
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $OutputDir         = (Join-Path $PSScriptRoot 'dist'),
    [string] $ModuleCacheDir    = (Join-Path $PSScriptRoot 'PSModuleCache'),
    [switch] $CreateZip         = $true,
    [switch] $SkipModuleDownload
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Pinned dependency manifest ────────────────────────────────────────

# Update these entries when upgrading Az module dependencies.
$script:PinnedModules = @(
    @{ Name = 'Az.Accounts'; Version = '2.15.1' }
)

#endregion ───────────────────────────────────────────────────────────────────

#region ── Helpers ───────────────────────────────────────────────────────────

function Write-Step {
    param([string]$Text)
    Write-Host "`n==> $Text" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Text)
    Write-Host "    $Text" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Text)
    Write-Host "    WARNING: $Text" -ForegroundColor Yellow
}

#endregion ───────────────────────────────────────────────────────────────────

#region ── Step 1 – Ensure PSModuleCache ─────────────────────────────────────

if (-not $SkipModuleDownload) {
    Write-Step 'Downloading pinned Az modules'

    if (-not (Test-Path $ModuleCacheDir)) {
        $null = New-Item -ItemType Directory -Path $ModuleCacheDir -Force
    }

    # Ensure PowerShellGet >= 2 is available for Save-Module
    $psget = Get-Module PowerShellGet -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $psget -or $psget.Version -lt [version]'1.6.0') {
        Write-Warn 'PowerShellGet 1.6+ not found. Attempting to install from PSGallery...'
        Install-Module PowerShellGet -Force -Scope CurrentUser -AllowClobber
    }

    foreach ($mod in $script:PinnedModules) {
        $modName    = $mod.Name
        $modVersion = $mod.Version
        $dest       = Join-Path $ModuleCacheDir $modName

        # Skip if already present at the pinned version
        $existingPsd = Join-Path $dest "$modVersion\$modName.psd1"
        if (Test-Path $existingPsd) {
            Write-Success "$modName $modVersion already cached – skipping."
            continue
        }

        Write-Host "    Saving $modName $modVersion to '$ModuleCacheDir'..." -ForegroundColor White
        if ($PSCmdlet.ShouldProcess("$modName@$modVersion", 'Save-Module')) {
            Save-Module -Name $modName -RequiredVersion $modVersion -Path $ModuleCacheDir -Force
            Write-Success "Saved $modName $modVersion"
        }
    }
} else {
    Write-Warn 'Module download skipped (-SkipModuleDownload).'
}

#endregion ───────────────────────────────────────────────────────────────────

#region ── Step 2 – Verify pinned module cache ───────────────────────────────

Write-Step 'Verifying pinned module versions in cache'

foreach ($mod in $script:PinnedModules) {
    $modName    = $mod.Name
    $modVersion = $mod.Version
    $psd1       = Join-Path $ModuleCacheDir "$modName\$modVersion\$modName.psd1"

    if (Test-Path $psd1) {
        Write-Success "$modName $modVersion – OK"
    } else {
        Write-Warn "$modName $modVersion – NOT FOUND at '$psd1'. Run without -SkipModuleDownload."
    }
}

#endregion ───────────────────────────────────────────────────────────────────

#region ── Step 3 – Generate integrity manifest ──────────────────────────────

Write-Step 'Generating integrity manifest (modules.sha256)'

$modulesPath   = Join-Path $PSScriptRoot 'Modules'
$manifestPath  = Join-Path $PSScriptRoot 'modules.sha256'

if (-not (Test-Path $modulesPath -PathType Container)) {
    throw "Modules directory not found: '$modulesPath'"
}

# Import Integrity module (no Az required)
$integrityMod = Join-Path $modulesPath 'Integrity.psm1'
if (-not (Test-Path $integrityMod)) {
    throw "Integrity module not found: '$integrityMod'"
}
Import-Module $integrityMod -Force -DisableNameChecking

if ($PSCmdlet.ShouldProcess($manifestPath, 'Write integrity manifest')) {
    New-ModuleIntegrityManifest -ModulesPath $modulesPath -ManifestPath $manifestPath -Verbose
    Write-Success "Manifest written: $manifestPath"
}

#endregion ───────────────────────────────────────────────────────────────────

#region ── Step 4 – Print manifest content ───────────────────────────────────

Write-Step 'Manifest content'
Get-Content $manifestPath | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }

#endregion ───────────────────────────────────────────────────────────────────

#region ── Step 5 – Create distribution zip ──────────────────────────────────

if ($CreateZip) {
    Write-Step "Creating distribution zip in '$OutputDir'"

    if (-not (Test-Path $OutputDir)) {
        $null = New-Item -ItemType Directory -Path $OutputDir -Force
    }

    $version   = (Get-Date -Format 'yyyyMMdd-HHmmss')
    $zipName   = "AzArmClient-PS-$version.zip"
    $zipPath   = Join-Path $OutputDir $zipName

    # Files / dirs to include in the zip
    $includes = @(
        (Join-Path $PSScriptRoot 'AzArmClient.ps1'),
        (Join-Path $PSScriptRoot 'modules.sha256'),
        (Join-Path $PSScriptRoot 'README.md'),
        (Join-Path $PSScriptRoot 'LICENSE'),
        $modulesPath
    )

    # PSModuleCache is optional (only if it exists)
    if (Test-Path $ModuleCacheDir) { $includes += $ModuleCacheDir }

    if ($PSCmdlet.ShouldProcess($zipPath, 'Create zip archive')) {
        # Use .NET for compatibility with PS 5.1
        Add-Type -AssemblyName System.IO.Compression.FileSystem

        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

        $zip = [System.IO.Compression.ZipFile]::Open($zipPath, 'Create')
        try {
            foreach ($item in $includes) {
                if (-not (Test-Path $item)) {
                    Write-Warn "Include path not found, skipping: $item"
                    continue
                }
                if (Test-Path $item -PathType Leaf) {
                    $entryName = Split-Path $item -Leaf
                    $null = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $item, $entryName)
                } else {
                    # Directory – recurse
                    $baseName = Split-Path $item -Leaf
                    Get-ChildItem $item -Recurse -File | ForEach-Object {
                        $rel  = $_.FullName.Substring($item.Length).TrimStart([IO.Path]::DirectorySeparatorChar)
                        $entry = "$baseName/$($rel.Replace([IO.Path]::DirectorySeparatorChar, '/'))"
                        $null = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $_.FullName, $entry)
                    }
                }
            }
        } finally {
            $zip.Dispose()
        }

        Write-Success "Archive created: $zipPath"
    }
}

#endregion ───────────────────────────────────────────────────────────────────

Write-Step 'Build complete'
