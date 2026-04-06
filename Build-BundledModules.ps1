<#
.SYNOPSIS
Maintainer-side packaging script that bundles Az modules and generates distributable manifests.

.DESCRIPTION
Build-BundledModules.ps1 downloads pinned module versions into a local Modules folder, captures dependency
versions, optionally signs tool-owned scripts, and generates Manifest\Versions.json and Manifest\Files.sha256.json.

.NOTES
Script Name: Build-BundledModules.ps1
Description: Maintainer build script for bundled Az module packaging.
Author: Blake Drumm (blakedrumm@microsoft.com)
Version: 1.0.1
Created Date: 2026-04-03
Last Updated Date: 2026-04-06
Requirements: Windows PowerShell 5.1 or PowerShell 7.x, internet access for maintainer builds, Save-PSResource preferred.
Notes: Runtime downloads are intentionally disallowed in ArmClient-PS.ps1. This script is the controlled packaging path.
#>
[CmdletBinding()]
param(
    [Parameter()][ValidateNotNullOrEmpty()][string]$ToolVersion='1.0.1',
    [Parameter()][switch]$Clean,
    [Parameter()][string]$OutputRoot,
    [Parameter()][string]$ModulesPath,
    [Parameter()][string]$ManifestPath,
    [Parameter()][switch]$Force,
    [Parameter()][switch]$DebugLogging,
    [Parameter()][string]$CodeSigningThumbprint,
    [Parameter()][switch]$SkipSigning,
    [Parameter()][switch]$SkipHashGeneration
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Enforce TLS 1.2 or higher for all HTTPS connections (required for government and production environments).
if ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Ssl3 -or
    [Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls -or
    -not ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$script:Configuration = [ordered]@{
    ScriptName                = 'Build-BundledModules.ps1'
    ToolScriptName            = 'ArmClient-PS.ps1'
    ToolName                  = 'ArmClient-PS'
    Author                    = 'Blake Drumm (blakedrumm@microsoft.com)'
    Version                   = '1.0.1'
    DefaultModulesFolderName  = 'Modules'
    DefaultManifestFolderName = 'Manifest'
    DefaultLogsFolderName     = 'Logs'
    VersionsManifestName      = 'Versions.json'
    FileHashManifestName      = 'Files.sha256.json'
    FileHashAlgorithm         = 'SHA256'
    TextFileExtensions        = @('.ps1','.psm1','.psd1','.ps1xml','.json','.txt','.xml','.help.txt')
    RequiredModules           = @(
        [pscustomobject]@{ Name='Az.Accounts'; Version='5.3.3'; Repository='PSGallery' }
    )
}

$script:ScriptPath = if ($PSCommandPath) { $PSCommandPath } elseif ($MyInvocation.MyCommand.Path) { $MyInvocation.MyCommand.Path } else { Join-Path (Get-Location).Path $script:Configuration.ScriptName }
$script:BuildState = [ordered]@{ ScriptRoot=$null; OutputRoot=$null; ModulesPath=$null; ManifestPath=$null; LogsPath=$null; LogFilePath=$null }

function Get-ScriptRoot { [CmdletBinding()] param() (Split-Path -Path $script:ScriptPath -Parent) }
function Ensure-Directory { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Path) if(-not (Test-Path -LiteralPath $Path)){ $null = New-Item -Path $Path -ItemType Directory -Force } }
function Get-SafeFullPath { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Path) ([IO.Path]::GetFullPath($Path)) }
function Get-RelativePathFromBase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$BasePath,
        [Parameter(Mandatory=$true)][string]$FullPath
    )
    $resolvedBase = [IO.Path]::GetFullPath($BasePath).TrimEnd('\','/')
    $resolvedFull = [IO.Path]::GetFullPath($FullPath)
    if (-not $resolvedFull.StartsWith($resolvedBase, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path '$FullPath' is not under base '$BasePath'."
    }
    $resolvedFull.Substring($resolvedBase.Length).TrimStart('\', '/')
}
function Write-Log { [CmdletBinding()] param([Parameter(Mandatory=$true)][ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level,[Parameter(Mandatory=$true)][string]$Message,[AllowNull()][object]$Data) if($Level -eq 'DEBUG' -and -not $DebugLogging){return}; $line='{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffK'),$Level,$Message; if($PSBoundParameters.ContainsKey('Data') -and $null -ne $Data){ try { $line='{0} | {1}' -f $line, ($Data | ConvertTo-Json -Depth 50 -Compress) } catch { $line='{0} | {1}' -f $line, (($Data | Out-String).Trim()) } }; if($script:BuildState.LogFilePath){ Add-Content -LiteralPath $script:BuildState.LogFilePath -Value $line -Encoding UTF8 }; Write-Output $line }
function Assert-PathUnderRoot { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Path,[Parameter(Mandatory=$true)][string]$Root) $resolvedPath=Get-SafeFullPath -Path $Path; $resolvedRoot=Get-SafeFullPath -Path $Root; if(-not $resolvedPath.StartsWith($resolvedRoot,[StringComparison]::OrdinalIgnoreCase)){ throw "Path '$resolvedPath' is outside of allowed root '$resolvedRoot'." } }

function Remove-GeneratedFileSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }

    try {
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        return
    }
    catch {
        Write-Log -Level 'DEBUG' -Message "Direct removal failed for '$Path'. Attempting overwrite cleanup." -Data $_.Exception.Message
    }

    Set-Content -LiteralPath $Path -Value $null -Encoding UTF8 -ErrorAction Stop
}

function Initialize-BuildFolders {
    [CmdletBinding()] param()
    $script:BuildState.ScriptRoot = Get-ScriptRoot
    $script:BuildState.OutputRoot = if($OutputRoot){ Get-SafeFullPath -Path $OutputRoot } else { $script:BuildState.ScriptRoot }
    $script:BuildState.ModulesPath = if($ModulesPath){ Get-SafeFullPath -Path $ModulesPath } else { Join-Path $script:BuildState.OutputRoot $script:Configuration.DefaultModulesFolderName }
    $script:BuildState.ManifestPath = if($ManifestPath){ Get-SafeFullPath -Path $ManifestPath } else { Join-Path $script:BuildState.OutputRoot $script:Configuration.DefaultManifestFolderName }
    $script:BuildState.LogsPath = Join-Path $script:BuildState.OutputRoot $script:Configuration.DefaultLogsFolderName
    $script:BuildState.LogFilePath = Join-Path $script:BuildState.LogsPath ('Build-BundledModules_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Ensure-Directory -Path $script:BuildState.OutputRoot; Ensure-Directory -Path $script:BuildState.ModulesPath; Ensure-Directory -Path $script:BuildState.ManifestPath; Ensure-Directory -Path $script:BuildState.LogsPath
    Write-Log -Level 'INFO' -Message ('Starting bundled module build for {0} {1}.' -f $script:Configuration.ToolName,$ToolVersion)
}

function Remove-ExistingBundledModules {
    [CmdletBinding()] param()
    Assert-PathUnderRoot -Path $script:BuildState.ModulesPath -Root $script:BuildState.OutputRoot
    Assert-PathUnderRoot -Path $script:BuildState.ManifestPath -Root $script:BuildState.OutputRoot
    if (Test-Path -LiteralPath $script:BuildState.ModulesPath) { Get-ChildItem -LiteralPath $script:BuildState.ModulesPath -Force | Remove-Item -Recurse -Force }
    foreach ($manifestFile in @((Join-Path $script:BuildState.ManifestPath $script:Configuration.VersionsManifestName),(Join-Path $script:BuildState.ManifestPath $script:Configuration.FileHashManifestName))) { Remove-GeneratedFileSafe -Path $manifestFile }
    Write-Log -Level 'INFO' -Message 'Removed previous bundled module content and generated manifests.'
}

function Get-PreferredSaveCommand { [CmdletBinding()] param() if(Get-Command -Name Save-PSResource -ErrorAction SilentlyContinue){ 'Save-PSResource' } elseif (Get-Command -Name Save-Module -ErrorAction SilentlyContinue) { 'Save-Module' } else { throw 'Neither Save-PSResource nor Save-Module is available. Install Microsoft.PowerShell.PSResourceGet or PowerShellGet on the maintainer machine before building the package.' } }
function Save-RequiredModules {
    [CmdletBinding()] param()
    $saveCommand = Get-PreferredSaveCommand
    Write-Log -Level 'INFO' -Message "Using '$saveCommand' to download pinned module versions."
    foreach ($requirement in $script:Configuration.RequiredModules) {
        $targetRoot = Join-Path $script:BuildState.ModulesPath $requirement.Name
        if (($Clean -or $Force) -and (Test-Path -LiteralPath $targetRoot)) { Assert-PathUnderRoot -Path $targetRoot -Root $script:BuildState.OutputRoot; Remove-Item -LiteralPath $targetRoot -Recurse -Force }
        Write-Log -Level 'INFO' -Message ('Saving module {0} {1} from {2}.' -f $requirement.Name,$requirement.Version,$requirement.Repository)
        if ($saveCommand -eq 'Save-PSResource') {
            $params = @{ Name=$requirement.Name; Version=$requirement.Version; Repository=$requirement.Repository; Path=$script:BuildState.ModulesPath; ErrorAction='Stop' }
            $command = Get-Command -Name Save-PSResource
            if ($command.Parameters.ContainsKey('TrustRepository')) { $params['TrustRepository'] = $true }
            if ($command.Parameters.ContainsKey('AcceptLicense')) { $params['AcceptLicense'] = $true }
            Save-PSResource @params | Out-Null
        } else {
            Save-Module -Name $requirement.Name -RequiredVersion $requirement.Version -Repository $requirement.Repository -Path $script:BuildState.ModulesPath -Force:$Force -ErrorAction Stop
        }
    }
}

function Import-ModuleManifestDataSafe { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$ManifestPath) try { Import-PowerShellDataFile -Path $ManifestPath } catch { throw "Unable to parse module manifest '$ManifestPath'. $($_.Exception.Message)" } }

function Get-ManifestValueSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$ManifestData,

        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    if ($ManifestData -is [System.Collections.IDictionary]) {
        if ($ManifestData.Contains($Name)) {
            return $ManifestData[$Name]
        }

        return $null
    }

    $property = $ManifestData.PSObject.Properties[$Name]
    if ($property) {
        return $property.Value
    }

    return $null
}

function Resolve-BundledDependencies {
    [CmdletBinding()] param()
    $requiredLookup = @{}
    foreach ($requirement in $script:Configuration.RequiredModules) { $requiredLookup["$($requirement.Name)|$($requirement.Version)"] = $true }
    $modules = foreach ($manifestFile in @(Get-ChildItem -LiteralPath $script:BuildState.ModulesPath -Recurse -Filter '*.psd1' -File)) {
        $manifestData = Import-ModuleManifestDataSafe -ManifestPath $manifestFile.FullName
        $moduleVersion = Get-ManifestValueSafe -ManifestData $manifestData -Name 'ModuleVersion'
        if (-not $moduleVersion) { continue }
        $rootModule = Get-ManifestValueSafe -ManifestData $manifestData -Name 'RootModule'
        $moduleName = if ($rootModule) { [IO.Path]::GetFileNameWithoutExtension([string]$rootModule) } else { [IO.Path]::GetFileNameWithoutExtension($manifestFile.Name) }
        $requiredModules = foreach ($requiredModule in @(Get-ManifestValueSafe -ManifestData $manifestData -Name 'RequiredModules')) {
            if ($null -eq $requiredModule) { continue }
            if ($requiredModule -is [string]) { $requiredModule }
            else {
                $requiredModuleName = Get-ManifestValueSafe -ManifestData $requiredModule -Name 'ModuleName'
                if (-not $requiredModuleName) {
                    $requiredModuleName = Get-ManifestValueSafe -ManifestData $requiredModule -Name 'Name'
                }

                if ($requiredModuleName) {
                    [string]$requiredModuleName
                }
            }
        }
        $key = "$moduleName|$moduleVersion"
        [pscustomobject]@{
            Name            = $moduleName
            Version         = [string]$moduleVersion
            Source          = if ($requiredLookup.ContainsKey($key)) { 'Pinned' } else { 'Dependency' }
            ManifestPath    = (Get-RelativePathFromBase -BasePath $script:BuildState.OutputRoot -FullPath $manifestFile.FullName).Replace('/','\')
            ModuleBase      = (Get-RelativePathFromBase -BasePath $script:BuildState.OutputRoot -FullPath $manifestFile.Directory.FullName).Replace('/','\')
            RequiredModules = @($requiredModules | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        }
    }
    @($modules | Sort-Object Name,Version -Unique)
}

function Find-CodeSigningCertificate {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Thumbprint)
    $normalized = $Thumbprint.Replace(' ','').ToUpperInvariant()
    foreach ($storePath in @('Cert:\CurrentUser\My','Cert:\LocalMachine\My')) {
        if (Test-Path -LiteralPath $storePath) {
            $certificate = Get-ChildItem -LiteralPath $storePath | Where-Object { $_.Thumbprint.ToUpperInvariant() -eq $normalized } | Select-Object -First 1
            if ($certificate) { return $certificate }
        }
    }
    throw "Code-signing certificate with thumbprint '$Thumbprint' was not found in CurrentUser\My or LocalMachine\My. Verify the thumbprint and certificate location before rebuilding."
}

function Set-ToolFileSignatures {
    [CmdletBinding()] param()
    if ($SkipSigning -or [string]::IsNullOrWhiteSpace($CodeSigningThumbprint)) { Write-Log -Level 'INFO' -Message 'Signing was skipped.'; return }
    $certificate = Find-CodeSigningCertificate -Thumbprint $CodeSigningThumbprint
    foreach ($filePath in @((Join-Path $script:BuildState.OutputRoot $script:Configuration.ToolScriptName),(Join-Path $script:BuildState.OutputRoot $script:Configuration.ScriptName))) {
        if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) { throw "Unable to sign missing file '$filePath'. Build the package contents first and then retry signing." }
        $signatureResult = Set-AuthenticodeSignature -FilePath $filePath -Certificate $certificate -ErrorAction Stop
        if ($signatureResult.Status -ne 'Valid') { throw "Code signing failed for '$filePath'. Status: $($signatureResult.Status). Verify the certificate chain and file access, then rebuild." }
        Write-Log -Level 'INFO' -Message "Signed '$filePath'."
    }
}

function New-VersionManifest {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][object[]]$ResolvedModules)
    $manifestObject = [ordered]@{
        schemaVersion = '1.0'
        tool = [ordered]@{ name=$script:Configuration.ToolName; version=$ToolVersion; builtUtc=(Get-Date).ToUniversalTime().ToString('o'); author=$script:Configuration.Author }
        requiredModules = @(
            foreach ($requirement in $script:Configuration.RequiredModules) { [ordered]@{ name=$requirement.Name; pinnedVersion=$requirement.Version; repository=$requirement.Repository } }
        )
        modules = @(
            foreach ($module in ($ResolvedModules | Sort-Object Name,Version)) { [ordered]@{ name=$module.Name; version=$module.Version; source=$module.Source; manifestPath=$module.ManifestPath; moduleBase=$module.ModuleBase; requiredModules=@($module.RequiredModules) } }
        )
    }
    $versionsManifestPath = Join-Path $script:BuildState.ManifestPath $script:Configuration.VersionsManifestName
    $manifestObject | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $versionsManifestPath -Encoding UTF8
    Write-Log -Level 'INFO' -Message "Generated '$versionsManifestPath'."
    $versionsManifestPath
}

function Get-ModuleFileInventory {
    [CmdletBinding()] param()
    $inventory = [Collections.Generic.List[object]]::new()
    foreach ($rootFile in @((Join-Path $script:BuildState.OutputRoot $script:Configuration.ToolScriptName),(Join-Path $script:BuildState.OutputRoot $script:Configuration.ScriptName),(Join-Path $script:BuildState.ManifestPath $script:Configuration.VersionsManifestName))) {
        if (Test-Path -LiteralPath $rootFile -PathType Leaf) { $inventory.Add([pscustomobject]@{ FullPath=$rootFile; RelativePath=(Get-RelativePathFromBase -BasePath $script:BuildState.OutputRoot -FullPath $rootFile).Replace('/','\') }) }
    }
    foreach ($moduleFile in @(Get-ChildItem -LiteralPath $script:BuildState.ModulesPath -Recurse -File)) { $inventory.Add([pscustomobject]@{ FullPath=$moduleFile.FullName; RelativePath=(Get-RelativePathFromBase -BasePath $script:BuildState.OutputRoot -FullPath $moduleFile.FullName).Replace('/','\') }) }
    @($inventory | Sort-Object RelativePath -Unique)
}
function Get-NormalizedFileHash {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$LiteralPath, [string]$Algorithm = 'SHA256')
    $ext = [IO.Path]::GetExtension($LiteralPath).ToLowerInvariant()
    if ($script:Configuration.TextFileExtensions -contains $ext) {
        $bytes = [IO.File]::ReadAllBytes($LiteralPath)
        $normalized = [Collections.Generic.List[byte]]::new($bytes.Length)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            if ($bytes[$i] -eq 0x0D -and ($i + 1) -lt $bytes.Length -and $bytes[$i + 1] -eq 0x0A) { continue }
            $normalized.Add($bytes[$i])
        }
        $hashImpl = [Security.Cryptography.HashAlgorithm]::Create($Algorithm)
        try { $hashBytes = $hashImpl.ComputeHash($normalized.ToArray()) } finally { $hashImpl.Dispose() }
        return ([BitConverter]::ToString($hashBytes).Replace('-','')).ToUpperInvariant()
    }
    (Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm).Hash.ToUpperInvariant()
}
function New-FileHashManifest {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][object[]]$FileInventory)
    if ($SkipHashGeneration) { Write-Log -Level 'WARN' -Message 'Hash manifest generation was skipped.'; return $null }
    $manifestObject = [ordered]@{
        schemaVersion = '1.0'
        generatedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        algorithm     = $script:Configuration.FileHashAlgorithm
        notes         = 'Files.sha256.json intentionally does not hash itself. Text-file hashes are computed after normalizing CRLF to LF for cross-platform consistency.'
        files         = @(
            foreach ($item in $FileInventory) {
                $hash = Get-NormalizedFileHash -LiteralPath $item.FullPath -Algorithm $script:Configuration.FileHashAlgorithm
                [ordered]@{ path=$item.RelativePath; algorithm=$script:Configuration.FileHashAlgorithm; hash=$hash; required=$true }
            }
        )
    }
    $fileHashManifestPath = Join-Path $script:BuildState.ManifestPath $script:Configuration.FileHashManifestName
    $manifestObject | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $fileHashManifestPath -Encoding UTF8
    Write-Log -Level 'INFO' -Message "Generated '$fileHashManifestPath'."
    $fileHashManifestPath
}

function Test-BuildOutput {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][object[]]$ResolvedModules)
    foreach ($path in @($script:BuildState.OutputRoot,$script:BuildState.ModulesPath,$script:BuildState.ManifestPath)) { if (-not (Test-Path -LiteralPath $path)) { throw "Expected build path '$path' is missing. Confirm the maintainer build has permission to create package folders in the selected output root." } }
    foreach ($requirement in $script:Configuration.RequiredModules) {
        $match = $ResolvedModules | Where-Object { $_.Name -eq $requirement.Name -and $_.Version -eq $requirement.Version }
        if (-not $match) { throw "Pinned module '$($requirement.Name)' version '$($requirement.Version)' was not found in the build output. The download may have failed or a different version was saved." }
    }
    $versionsManifestPath = Join-Path $script:BuildState.ManifestPath $script:Configuration.VersionsManifestName
    if (-not (Test-Path -LiteralPath $versionsManifestPath -PathType Leaf)) { throw "Missing versions manifest '$versionsManifestPath'. The package metadata step did not complete successfully." }
    if (-not $SkipHashGeneration) { $fileHashManifestPath = Join-Path $script:BuildState.ManifestPath $script:Configuration.FileHashManifestName; if (-not (Test-Path -LiteralPath $fileHashManifestPath -PathType Leaf)) { throw "Missing hash manifest '$fileHashManifestPath'. Re-run the build without -SkipHashGeneration for a distributable package." } }
    Write-Log -Level 'INFO' -Message 'Build output validation completed successfully.'
}

function Invoke-BundledModuleBuild {
    [CmdletBinding()] param()
    Initialize-BuildFolders
    if ($Clean) { Remove-ExistingBundledModules; Ensure-Directory -Path $script:BuildState.ModulesPath; Ensure-Directory -Path $script:BuildState.ManifestPath }
    Save-RequiredModules
    $resolvedModules = Resolve-BundledDependencies
    $null = New-VersionManifest -ResolvedModules $resolvedModules
    Set-ToolFileSignatures
    $fileInventory = Get-ModuleFileInventory
    $null = New-FileHashManifest -FileInventory $fileInventory
    Test-BuildOutput -ResolvedModules $resolvedModules
    Write-Log -Level 'INFO' -Message 'Bundled module build completed successfully.'
}

try { Invoke-BundledModuleBuild } catch { Write-Log -Level 'ERROR' -Message $_.Exception.Message; throw }
