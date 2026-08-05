<#
.SYNOPSIS
Creates release notes for an AzArmClient-PS GitHub release.

.DESCRIPTION
Formats one or more additions as a change log and appends an asset-specific
GitHub download-count badge for the release version.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$')]
    [string]$Version,

    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[^/]+/[^/]+$')]
    [string]$Repository,

    [Parameter()]
    [AllowEmptyString()]
    [string]$Additions,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AssetName = 'AzArmClient-PS.zip',

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$additionLines = [Collections.Generic.List[string]]::new()
foreach ($line in @($Additions -split '\r?\n')) {
    $trimmedLine = $line.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmedLine)) { continue }
    if ($trimmedLine.StartsWith('- ')) {
        $additionLines.Add($trimmedLine)
    }
    else {
        $additionLines.Add("- $trimmedLine")
    }
}

if ($additionLines.Count -eq 0) {
    $additionLines.Add("- Released AzArmClient-PS version $Version.")
}

$tagName = "v$Version"
$badgeUrl = "https://img.shields.io/github/downloads/$Repository/$tagName/$AssetName`?style=for-the-badge&color=brightgreen"
$downloadUrl = "https://github.com/$Repository/releases/download/$tagName/$AssetName"
$content = @(
    '# Change Log'
    ''
    '## Additions'
    $additionLines.ToArray()
    ''
    "[![Download Count $tagName]($badgeUrl)]($downloadUrl)"
) -join [Environment]::NewLine

$parentPath = Split-Path -Path $OutputPath -Parent
if ($parentPath -and -not (Test-Path -LiteralPath $parentPath)) {
    $null = New-Item -Path $parentPath -ItemType Directory -Force
}

[IO.File]::WriteAllText($OutputPath, $content + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
Get-Item -LiteralPath $OutputPath