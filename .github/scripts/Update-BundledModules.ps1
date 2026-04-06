<#
.SYNOPSIS
Checks for newer versions of bundled PowerShell modules and updates the repository when upgrades are available.

.DESCRIPTION
Update-BundledModules.ps1 queries the PowerShell Gallery for the latest stable version of each module listed in
Build-BundledModules.ps1, updates the pinned version when a newer release exists, bumps the tool version (patch),
and re-runs the build to regenerate Modules/, Manifest/Versions.json, and Manifest/Files.sha256.json.

Designed for unattended execution inside a GitHub Actions workflow.

.NOTES
Script Name: Update-BundledModules.ps1
Author: Blake Drumm (blakedrumm@microsoft.com)
Requirements: PowerShell 7.x, internet access to PSGallery.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Enforce TLS 1.2 or higher for all HTTPS connections.
if ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Ssl3 -or
    [Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls -or
    -not ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$repoRoot = (Resolve-Path -Path (Join-Path $PSScriptRoot '..' '..')).Path
$buildScript = Join-Path $repoRoot 'Build-BundledModules.ps1'
$mainScript = Join-Path $repoRoot 'ArmClient-PS.ps1'
$versionsManifest = Join-Path $repoRoot 'Manifest' 'Versions.json'

# Resolve all repo-owned entry points up front so the workflow fails fast if it
# is executed from an unexpected checkout layout.
if (-not (Test-Path -LiteralPath $buildScript -PathType Leaf)) {
    throw "Build script not found at '$buildScript'."
}
if (-not (Test-Path -LiteralPath $mainScript -PathType Leaf)) {
    throw "Main script not found at '$mainScript'."
}

# ---------------------------------------------------------------------------
# 1. Parse current pinned modules from Build-BundledModules.ps1
# ---------------------------------------------------------------------------
Write-Output '--- Parsing current pinned module versions ---'
$buildContent = Get-Content -LiteralPath $buildScript -Raw

# Extract all module entries: Name='ModuleName'; Version='x.y.z'
$modulePattern = [regex]"\[pscustomobject\]@\{\s*Name\s*=\s*'([^']+)'\s*;\s*Version\s*=\s*'([^']+)'\s*;\s*Repository\s*=\s*'([^']+)'\s*\}"
$moduleMatches = $modulePattern.Matches($buildContent)

if ($moduleMatches.Count -eq 0) {
    throw 'No pinned modules found in Build-BundledModules.ps1.'
}

$updates = @()
foreach ($match in $moduleMatches) {
    $moduleName = $match.Groups[1].Value
    $currentVersion = $match.Groups[2].Value
    $repository = $match.Groups[3].Value

    Write-Output "  Module: $moduleName  Current: $currentVersion  Repository: $repository"

    # Query PSGallery for the latest stable version.
    $latestModule = Find-Module -Name $moduleName -Repository $repository -ErrorAction Stop
    $latestVersion = $latestModule.Version

    Write-Output "  Latest available: $latestVersion"

    # Only queue true upgrades; equal or older versions are left untouched so
    # automated update runs remain idempotent.
    if ([version]$latestVersion -gt [version]$currentVersion) {
        Write-Output "  >> UPDATE AVAILABLE: $currentVersion -> $latestVersion"
        $updates += [pscustomobject]@{
            Name           = $moduleName
            OldVersion     = $currentVersion
            NewVersion     = [string]$latestVersion
            Repository     = $repository
            MatchValue     = $match.Value
        }
    }
    else {
        Write-Output "  Already up to date."
    }
}

if ($updates.Count -eq 0) {
    Write-Output ''
    Write-Output '=== All modules are up to date. No changes needed. ==='
    # Signal to the workflow that no commit is required.
    if ($env:GITHUB_OUTPUT) {
        Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value 'has_updates=false'
    }
    exit 0
}

# ---------------------------------------------------------------------------
# 2. Update pinned versions in Build-BundledModules.ps1
# ---------------------------------------------------------------------------
Write-Output ''
Write-Output '--- Updating pinned versions in Build-BundledModules.ps1 ---'

$updatedBuildContent = $buildContent
foreach ($update in $updates) {
    $oldEntry = $update.MatchValue
    # Replace the exact pinned module entry that was parsed earlier so the
    # update stays constrained to the intended requirement line.
    $newEntry = $oldEntry.Replace("Version='$($update.OldVersion)'", "Version='$($update.NewVersion)'")
    $updatedBuildContent = $updatedBuildContent.Replace($oldEntry, $newEntry)
    Write-Output "  Updated $($update.Name): $($update.OldVersion) -> $($update.NewVersion)"
}

# ---------------------------------------------------------------------------
# 3. Bump tool version (patch increment)
# ---------------------------------------------------------------------------
Write-Output ''
Write-Output '--- Bumping tool version ---'

# Read current tool version from Versions.json (authoritative source).
$currentToolVersion = '1.0.0'
if (Test-Path -LiteralPath $versionsManifest -PathType Leaf) {
    $versionsData = Get-Content -LiteralPath $versionsManifest -Raw | ConvertFrom-Json
    $currentToolVersion = $versionsData.tool.version
}

# The maintenance workflow treats a module refresh as a patch-level tool change
# because the packaged contents changed even when the script interface did not.
$versionParts = $currentToolVersion.Split('.')
$major = [int]$versionParts[0]
$minor = [int]$versionParts[1]
$patch = [int]$versionParts[2]
$patch++
$newToolVersion = "$major.$minor.$patch"

Write-Output "  Tool version: $currentToolVersion -> $newToolVersion"

# Update the ToolVersion default in Build-BundledModules.ps1.
$updatedBuildContent = $updatedBuildContent -replace "(\[string\]\`$ToolVersion\s*=\s*')[^']+(')", "`${1}$newToolVersion`${2}"

# Update the Version in the Configuration block of Build-BundledModules.ps1.
# Match the specific line: Version = 'x.y.z' inside $script:Configuration
$updatedBuildContent = [regex]::Replace(
    $updatedBuildContent,
    "(?<=\`$script:Configuration\s*=\s*\[ordered\]@\{[\s\S]*?^\s*Version\s*=\s*')[^']+(?=')",
    $newToolVersion,
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)

# Update header Version comment line in Build-BundledModules.ps1.
$updatedBuildContent = $updatedBuildContent -replace '(?m)^(Version:\s+)\S+', "`${1}$newToolVersion"

# Update Last Updated Date in Build-BundledModules.ps1 header.
$todayDate = (Get-Date).ToString('yyyy-MM-dd')
$updatedBuildContent = $updatedBuildContent -replace '(?m)^(Last Updated Date:\s+)\S+', "`${1}$todayDate"

Set-Content -LiteralPath $buildScript -Value $updatedBuildContent -NoNewline -Encoding UTF8

# Update version in ArmClient-PS.ps1 header comment and Configuration block.
$mainContent = Get-Content -LiteralPath $mainScript -Raw

# Update header Version comment line.
$mainContent = $mainContent -replace '(?m)^(Version:\s+)\S+', "`${1}$newToolVersion"

# Update Last Updated Date in ArmClient-PS.ps1 header.
$mainContent = $mainContent -replace '(?m)^(Last Updated Date:\s+)\S+', "`${1}$todayDate"

# Update Version in the $script:Configuration block of ArmClient-PS.ps1.
$mainContent = [regex]::Replace(
    $mainContent,
    "(?<=\`$script:Configuration\s*=\s*\[ordered\]@\{[\s\S]*?^\s*Version\s*=\s*')[^']+(?=')",
    $newToolVersion,
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)

Set-Content -LiteralPath $mainScript -Value $mainContent -NoNewline -Encoding UTF8

# ---------------------------------------------------------------------------
# 4. Run the build to regenerate modules and manifests
# ---------------------------------------------------------------------------
Write-Output ''
Write-Output '--- Running Build-BundledModules.ps1 -Clean -SkipSigning ---'

# The rebuild step is what actually refreshes Modules/ and regenerates the
# manifests after the pinned versions and tool version have been updated.
Push-Location $repoRoot
try {
    & $buildScript -ToolVersion $newToolVersion -Clean -SkipSigning -Force
}
finally {
    Pop-Location
}

Write-Output ''
Write-Output '=== Build completed successfully. ==='

# ---------------------------------------------------------------------------
# 5. Output summary for the workflow
# ---------------------------------------------------------------------------
$summaryParts = @()
foreach ($update in $updates) {
    $summaryParts += "$($update.Name) $($update.OldVersion) -> $($update.NewVersion)"
}
$commitSummary = $summaryParts -join ', '

if ($env:GITHUB_OUTPUT) {
    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value 'has_updates=true'
    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "commit_summary=$commitSummary"
    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value "new_tool_version=$newToolVersion"
}

Write-Output "Updates applied: $commitSummary"
Write-Output "New tool version: $newToolVersion"
