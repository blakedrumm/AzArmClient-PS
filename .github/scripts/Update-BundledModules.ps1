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

function Initialize-PSGalleryRepository {
    [CmdletBinding()]
    param([Parameter()][string]$RepositoryName = 'PSGallery')

    # Unattended runners do not always have PSGallery registered yet. The original
    # workflow only called Set-PSRepository, which throws a terminating error when
    # the source is missing (e.g. "No repository with the name 'PSGallery' was
    # found"). That aborted the job before the build ran, so Modules/, Versions.json
    # and Files.sha256.json were never rebuilt. Register the source when it is
    # absent and trust it, tolerating any provider quirks so the run can continue.

    # PowerShellGet (V2): register the default gallery when missing, then trust it
    # so Find-Module / Save-Module never prompt during non-interactive runs.
    if (Get-Command -Name Get-PSRepository -ErrorAction SilentlyContinue) {
        if (-not (Get-PSRepository -Name $RepositoryName -ErrorAction SilentlyContinue)) {
            try { Register-PSRepository -Default -ErrorAction Stop 2>$null }
            catch { Write-Output "  Could not register default PSRepository: $($_.Exception.Message)" }
        }
        if (Get-PSRepository -Name $RepositoryName -ErrorAction SilentlyContinue) {
            try { Set-PSRepository -Name $RepositoryName -InstallationPolicy Trusted -ErrorAction Stop 2>$null }
            catch { Write-Output "  Could not set PSRepository trust: $($_.Exception.Message)" }
        }
    }

    # PSResourceGet (V3): PSGallery ships registered by default, but register it
    # when absent and ensure it is trusted for non-interactive Save-PSResource.
    if (Get-Command -Name Get-PSResourceRepository -ErrorAction SilentlyContinue) {
        if (-not (Get-PSResourceRepository -Name $RepositoryName -ErrorAction SilentlyContinue)) {
            try { Register-PSResourceRepository -PSGallery -Trusted -ErrorAction Stop 2>$null }
            catch { Write-Output "  Could not register PSResource PSGallery: $($_.Exception.Message)" }
        }
        elseif (Get-Command -Name Set-PSResourceRepository -ErrorAction SilentlyContinue) {
            try { Set-PSResourceRepository -Name $RepositoryName -Trusted -ErrorAction Stop 2>$null }
            catch { Write-Output "  Could not set PSResourceRepository trust: $($_.Exception.Message)" }
        }
    }
}

function Get-VersionTokenMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Content,
        [Parameter(Mandatory=$true)][string]$Pattern,
        [Parameter(Mandatory=$true)][string]$Description
    )

    # PowerShell's -replace silently returns the input unchanged when its anchor
    # stops matching, which let a half-applied version bump reach the commit step.
    # Requiring exactly one match turns anchor drift into a failed run instead.
    $found = [regex]::Matches($Content, $Pattern, [Text.RegularExpressions.RegexOptions]::Multiline)
    if ($found.Count -ne 1) {
        throw "Expected exactly one '$Description' site but found $($found.Count). The Update-BundledModules.ps1 anchor no longer matches the target file."
    }
    $found[0].Groups['value']
}

function Get-VersionToken {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)][string]$Content,
        [Parameter(Mandatory=$true)][string]$Pattern,
        [Parameter(Mandatory=$true)][string]$Description
    )

    (Get-VersionTokenMatch -Content $Content -Pattern $Pattern -Description $Description).Value
}

function Set-VersionToken {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)][string]$Content,
        [Parameter(Mandatory=$true)][string]$Pattern,
        [Parameter(Mandatory=$true)][string]$NewValue,
        [Parameter(Mandatory=$true)][string]$Description
    )

    # Rewrite only the captured span so no replacement-string escaping is involved.
    $value = Get-VersionTokenMatch -Content $Content -Pattern $Pattern -Description $Description
    $Content.Remove($value.Index, $value.Length).Insert($value.Index, $NewValue)
}

function Write-GitHubOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')][string]$Name,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Value
    )

    # Values derive from PowerShell Gallery metadata. A bare "name=value" line lets
    # an embedded newline forge extra step outputs, so use the delimited form with
    # a delimiter that cannot appear in the value.
    if ([string]::IsNullOrWhiteSpace($env:GITHUB_OUTPUT)) { return }

    $normalized = $Value.Replace("`r`n", "`n").Replace("`r", "`n")
    do { $delimiter = 'ghadelimiter_{0}' -f [guid]::NewGuid().ToString('N') }
    while (($normalized -split "`n") -ccontains $delimiter)

    $record = "$Name<<$delimiter`n$normalized`n$delimiter`n"
    [IO.File]::AppendAllText($env:GITHUB_OUTPUT, $record, [Text.UTF8Encoding]::new($false))
}

# Every file-based site that must carry the tool version. The bump and the
# post-build assertion both read this list so a site cannot be added to one only.
$versionSites = @(
    [pscustomobject]@{ Name='Build-BundledModules.ps1 -ToolVersion default';  Script='build'; Pattern="\[string\]\`$ToolVersion\s*=\s*'(?<value>[^']+)'" }
    [pscustomobject]@{ Name='Build-BundledModules.ps1 header';                Script='build'; Pattern="^Version:[ \t]+(?<value>\S+)" }
    [pscustomobject]@{ Name='Build-BundledModules.ps1 Configuration.Version'; Script='build'; Pattern="\`$script:Configuration\s*=\s*\[ordered\]@\{[\s\S]*?^\s*Version\s*=\s*'(?<value>[^']+)'" }
    [pscustomobject]@{ Name='ArmClient-PS.ps1 header';                        Script='main';  Pattern="^Version:[ \t]+(?<value>\S+)" }
    [pscustomobject]@{ Name='ArmClient-PS.ps1 Configuration.Version';         Script='main';  Pattern="\`$script:Configuration\s*=\s*\[ordered\]@\{[\s\S]*?^\s*Version\s*=\s*'(?<value>[^']+)'" }
)

$dateSites = @(
    [pscustomobject]@{ Name='Build-BundledModules.ps1 Last Updated Date'; Script='build'; Pattern="^Last Updated Date:[ \t]+(?<value>\S+)" }
    [pscustomobject]@{ Name='ArmClient-PS.ps1 Last Updated Date';         Script='main';  Pattern="^Last Updated Date:[ \t]+(?<value>\S+)" }
)

# ---------------------------------------------------------------------------
# 1. Parse current pinned modules from Build-BundledModules.ps1
# ---------------------------------------------------------------------------
Write-Output '--- Ensuring PSGallery is registered and trusted ---'
# Runs in the same session that later invokes the build, so the registration
# also covers the build's Save-PSResource / Save-Module download step.
Initialize-PSGalleryRepository

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
    Write-GitHubOutput -Name 'has_updates' -Value 'false'
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

# Read current tool version from Versions.json (authoritative source). A missing
# manifest previously defaulted to 1.0.0, which would silently rewind the version.
if (-not (Test-Path -LiteralPath $versionsManifest -PathType Leaf)) {
    throw "Versions manifest not found at '$versionsManifest'. Build the package before running the update job."
}
$versionsData = Get-Content -LiteralPath $versionsManifest -Raw | ConvertFrom-Json
$currentToolVersion = [string]$versionsData.tool.version

# The maintenance workflow treats a module refresh as a patch-level tool change
# because the packaged contents changed even when the script interface did not.
# release.yml tolerates semver prerelease suffixes, but incrementing one has no
# defensible unattended meaning, so require a plain three-part version here.
$versionMatch = [regex]::Match($currentToolVersion, '^(\d+)\.(\d+)\.(\d+)$')
if (-not $versionMatch.Success) {
    throw "Tool version '$currentToolVersion' in '$versionsManifest' must be a three-part numeric version such as '1.2.3' to be bumped automatically."
}
$newToolVersion = '{0}.{1}.{2}' -f $versionMatch.Groups[1].Value, $versionMatch.Groups[2].Value, ([int]$versionMatch.Groups[3].Value + 1)

Write-Output "  Tool version: $currentToolVersion -> $newToolVersion"

$todayDate = (Get-Date).ToString('yyyy-MM-dd')
$scriptContent = @{
    build = $updatedBuildContent
    main  = Get-Content -LiteralPath $mainScript -Raw
}

foreach ($site in $versionSites) {
    $scriptContent[$site.Script] = Set-VersionToken -Content $scriptContent[$site.Script] -Pattern $site.Pattern -NewValue $newToolVersion -Description $site.Name
}
foreach ($site in $dateSites) {
    $scriptContent[$site.Script] = Set-VersionToken -Content $scriptContent[$site.Script] -Pattern $site.Pattern -NewValue $todayDate -Description $site.Name
}

Set-Content -LiteralPath $buildScript -Value $scriptContent['build'] -NoNewline -Encoding UTF8
Set-Content -LiteralPath $mainScript -Value $scriptContent['main'] -NoNewline -Encoding UTF8

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
# 5. Assert every version site agrees before the workflow may commit
# ---------------------------------------------------------------------------
# has_updates=true is what authorizes the commit and push steps, so a bump that
# only partially landed has to fail here rather than reach the default branch.
Write-Output ''
Write-Output '--- Verifying version consistency ---'

$verifiedContent = @{
    build = Get-Content -LiteralPath $buildScript -Raw
    main  = Get-Content -LiteralPath $mainScript -Raw
}
$observedVersions = [ordered]@{
    'Manifest/Versions.json tool.version' = [string](Get-Content -LiteralPath $versionsManifest -Raw | ConvertFrom-Json).tool.version
}
foreach ($site in $versionSites) {
    $observedVersions[$site.Name] = Get-VersionToken -Content $verifiedContent[$site.Script] -Pattern $site.Pattern -Description $site.Name
}

$driftedSites = @($observedVersions.GetEnumerator() | Where-Object { $_.Value -cne $newToolVersion })
if ($driftedSites.Count -gt 0) {
    $detail = ($observedVersions.GetEnumerator() | ForEach-Object { "$($_.Key)='$($_.Value)'" }) -join '; '
    throw "Version bump did not land consistently. Expected '$newToolVersion' at every site but observed: $detail"
}
Write-Output "  Confirmed '$newToolVersion' at $($observedVersions.Count) version sites."

# ---------------------------------------------------------------------------
# 6. Output summary for the workflow
# ---------------------------------------------------------------------------
$summaryParts = @()
foreach ($update in $updates) {
    $summaryParts += "$($update.Name) $($update.OldVersion) -> $($update.NewVersion)"
}
$commitSummary = $summaryParts -join ', '

Write-GitHubOutput -Name 'has_updates' -Value 'true'
Write-GitHubOutput -Name 'commit_summary' -Value $commitSummary
Write-GitHubOutput -Name 'new_tool_version' -Value $newToolVersion

Write-Output "Updates applied: $commitSummary"
Write-Output "New tool version: $newToolVersion"
