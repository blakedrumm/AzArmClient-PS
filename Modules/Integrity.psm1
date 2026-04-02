#Requires -Version 5.1
<#
.SYNOPSIS
    Module-integrity validation for AzArmClient-PS.

.DESCRIPTION
    Computes and verifies SHA-256 hashes of the Modules files listed in a
    manifest (modules.sha256) so that tampered or corrupted files are detected
    before they are imported.

.NOTES
    Part of AzArmClient-PS.
#>

Set-StrictMode -Version Latest

# Expected manifest file name (relative to the script root)
$script:ManifestName = 'modules.sha256'

<#
.SYNOPSIS
    Computes the SHA-256 hash of a file and returns it as a lowercase hex string.

.PARAMETER FilePath
    Path to the file to hash.
#>
function Get-FileHashSHA256 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $FilePath
    )

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        throw "File not found: '$FilePath'"
    }

    $algo = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($FilePath)
        try {
            $bytes = $algo.ComputeHash($stream)
        } finally {
            $stream.Dispose()
        }
    } finally {
        $algo.Dispose()
    }

    return [System.BitConverter]::ToString($bytes).Replace('-', '').ToLower()
}

<#
.SYNOPSIS
    Builds a SHA-256 manifest for every *.psm1 file under a given directory.

.DESCRIPTION
    Writes a plain-text file where each non-blank line has the format:
        <sha256hex>  <relative-path>
    Paths are relative to the directory containing the manifest and use
    forward-slash separators for portability.

.PARAMETER ModulesPath
    Root directory of the Modules folder.

.PARAMETER ManifestPath
    Full path of the output manifest file.  Defaults to
    <ModulesPath>/../modules.sha256.
#>
function New-ModuleIntegrityManifest {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string] $ModulesPath,

        [string] $ManifestPath
    )

    if (-not $ManifestPath) {
        $ManifestPath = Join-Path (Split-Path -Parent $ModulesPath) $script:ManifestName
    }

    $files = @(Get-ChildItem -LiteralPath $ModulesPath -Filter '*.psm1' -Recurse |
               Sort-Object FullName)

    $lines = foreach ($f in $files) {
        $hash      = Get-FileHashSHA256 -FilePath $f.FullName
        $rawSuffix = $f.FullName.Substring($ModulesPath.Length)
        $trimmed   = $rawSuffix.TrimStart([IO.Path]::DirectorySeparatorChar)
        $relPath   = $trimmed.Replace([IO.Path]::DirectorySeparatorChar, '/')
        "$hash  Modules/$relPath"
    }

    if ($PSCmdlet.ShouldProcess($ManifestPath, 'Write integrity manifest')) {
        Set-Content -LiteralPath $ManifestPath -Value $lines -Encoding UTF8
        Write-Verbose "Manifest written to '$ManifestPath' ($($files.Count) files)."
    }
}

<#
.SYNOPSIS
    Verifies the SHA-256 hashes of module files against a manifest.

.DESCRIPTION
    Reads the manifest produced by New-ModuleIntegrityManifest and re-hashes
    each listed file.  Throws a terminating error if any file is missing,
    has been tampered with, or if the manifest itself is absent.

.PARAMETER RootPath
    The repository / distribution root directory (the directory that contains
    both the Modules folder and the manifest file).

.PARAMETER ManifestPath
    Optional override for the manifest file path.
#>
function Test-ModuleIntegrity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $RootPath,

        [string] $ManifestPath
    )

    if (-not $ManifestPath) {
        $ManifestPath = Join-Path $RootPath $script:ManifestName
    }

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "Integrity manifest not found at '$ManifestPath'. " +
              "Run New-ModuleIntegrityManifest to create it."
    }

    $failures = [System.Collections.Generic.List[string]]::new()

    foreach ($rawLine in (Get-Content -LiteralPath $ManifestPath -Encoding UTF8)) {
        $line = $rawLine.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }

        # Format: <sha256>  <relative-path>
        $parts = $line -split '\s+', 2
        if ($parts.Count -ne 2) {
            $failures.Add("Malformed manifest line: '$line'")
            continue
        }

        $expected = $parts[0].ToLower()
        $relPath  = $parts[1].Replace('/', [IO.Path]::DirectorySeparatorChar)
        $fullPath = Join-Path $RootPath $relPath

        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            $failures.Add("Missing file: '$relPath'")
            continue
        }

        $actual = Get-FileHashSHA256 -FilePath $fullPath
        if ($actual -ne $expected) {
            $failures.Add("Hash mismatch for '$relPath': expected $expected, got $actual")
        }
    }

    if ($failures.Count -gt 0) {
        throw "Module integrity check FAILED:`n" + ($failures -join "`n")
    }

    Write-Verbose 'Module integrity check passed.'
}

Export-ModuleMember -Function Get-FileHashSHA256, New-ModuleIntegrityManifest, Test-ModuleIntegrity
