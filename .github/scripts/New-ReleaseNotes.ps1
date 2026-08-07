<#
.SYNOPSIS
Creates release notes for an AzArmClient-PS GitHub release.

.DESCRIPTION
Formats one or more additions as a change log, records the commit and archive
checksum the release was built from, and appends an asset-specific GitHub
download-count badge for the release version.
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
    [string]$Additions = '',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AssetName = 'AzArmClient-PS.zip',

    [Parameter()]
    [AllowEmptyString()]
    [ValidatePattern('^(?:[0-9a-fA-F]{40})?$')]
    [string]$Commit = '',

    [Parameter()]
    [AllowEmptyString()]
    [ValidatePattern('^(?:[0-9a-fA-F]{64})?$')]
    [string]$ArchiveSha256 = '',

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$additionLines = [Collections.Generic.List[string]]::new()
foreach ($line in @($Additions -split '\r?\n')) {
    # Additions are operator-supplied workflow input rendered into a public
    # release body; drop control characters that could corrupt the markdown.
    $trimmedLine = ([regex]::Replace($line, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '')).Trim()
    if ([string]::IsNullOrWhiteSpace($trimmedLine)) { continue }
    $additionLines.Add('- ' + ($trimmedLine -replace '^[-*+]\s+', ''))
}

if ($additionLines.Count -eq 0) {
    $additionLines.Add("- Released AzArmClient-PS version $Version.")
}

$provenanceLines = [Collections.Generic.List[string]]::new()
if ($Commit) { $provenanceLines.Add("- Built from commit ``$Commit``.") }
if ($ArchiveSha256) { $provenanceLines.Add("- ``$AssetName`` SHA-256: ``$($ArchiveSha256.ToLowerInvariant())``") }

$tagName = "v$Version"
$assetSegment = [Uri]::EscapeDataString($AssetName)
$badgeUrl = "https://img.shields.io/github/downloads/$Repository/$tagName/$assetSegment`?style=for-the-badge&color=brightgreen"
$downloadUrl = "https://github.com/$Repository/releases/download/$tagName/$assetSegment"
$content = @(
    '# Change Log'
    ''
    '## Additions'
    $additionLines.ToArray()
    if ($provenanceLines.Count -gt 0) {
        ''
        '## Package provenance'
        $provenanceLines.ToArray()
    }
    ''
    "[![Download Count $tagName]($badgeUrl)]($downloadUrl)"
) -join [Environment]::NewLine

$parentPath = Split-Path -Path $OutputPath -Parent
if ($parentPath -and -not (Test-Path -LiteralPath $parentPath)) {
    $null = New-Item -Path $parentPath -ItemType Directory -Force
}

[IO.File]::WriteAllText($OutputPath, $content + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
Get-Item -LiteralPath $OutputPath