<#
.SYNOPSIS
ARM-focused support utility that recreates the core ARMClient experience by using bundled Az modules.

.DESCRIPTION
ArmClient-PS.ps1 is a single-file, distributable PowerShell script that performs Azure Resource Manager
operations with Invoke-AzRestMethod while loading Az modules from a sibling Modules folder or, when safe,
from newer locally installed module versions.

.PARAMETER Method
HTTP method for the ARM request. Supported values are GET, POST, PUT, PATCH, and DELETE.

.PARAMETER Uri
Full ARM URI to invoke.

.PARAMETER RelativePath
Relative ARM path such as /subscriptions/<id>/resourceGroups/<name>.

.PARAMETER Operation
Predefined ARM operation preset name that resolves the request method, path template, and default api-version.

.PARAMETER OperationParameters
Hashtable of values used to fill placeholders for a predefined operation preset.

.PARAMETER ListOperations
Outputs the catalog of built-in operation presets.

.PARAMETER ShowOperationDetails
Outputs the full definition for the selected operation preset.

.PARAMETER ApiVersions
Outputs the relevant API versions for the selected operation preset.

.NOTES
Script Name: ArmClient-PS.ps1
Description: Secure ARM-focused REST support utility that uses bundled Az modules.
Author: Blake Drumm (blakedrumm@microsoft.com)
Version: 1.0.1
Created Date: 2026-04-03
Last Updated Date: 2026-04-06
Requirements: Windows PowerShell 5.1 or PowerShell 7.x, bundled Az.Accounts module and dependencies.
Environments: Supports all Azure cloud environments including AzureCloud, AzureUSGovernment, AzureChinaCloud,
              AzureUSNat, AzureUSSec, and custom environments registered with Add-AzEnvironment (e.g. Azure Stack).
Notes: Do not log tokens or secrets. Default behavior disables Az context autosave for the current process.
#>
[CmdletBinding(DefaultParameterSetName='Utility')]
param(
    [Parameter()][ValidateSet('GET','POST','PUT','PATCH','DELETE')][string]$Method='GET',
    [Parameter(ParameterSetName='RequestByUri')][System.Uri]$Uri,
    [Parameter(ParameterSetName='RequestByRelativePath')][string]$RelativePath,
    [Parameter()][string]$Operation,
    [Parameter()][hashtable]$OperationParameters,
    [Parameter()][string]$ApiVersion,
    [Parameter()][switch]$ApiVersions,
    [Parameter()][string]$Body,
    [Parameter()][string]$BodyFile,
    [Parameter()][string]$OutputFile,
    [Parameter()][switch]$RawOutput,
    [Parameter()][hashtable]$Headers,
    [Parameter()][string]$TenantId,
    [Parameter()][string]$SubscriptionId,
    [Parameter()][string]$Environment='AzureCloud',
    [Parameter()][switch]$UseManagedIdentity,
    [Parameter()][switch]$UseDeviceCode,
    [Parameter()][switch]$NoLogin,
    [Parameter()][switch]$ClearContextOnExit,
    [Parameter()][switch]$DebugLogging,
    [Parameter()][string]$LogPath,
    [Parameter()][switch]$SkipHashValidation,
    [Parameter()][switch]$EnforceSignatureValidation,
    [Parameter()][switch]$PreferBundledModules,
    [Parameter()][switch]$PreferInstalledModules,
    [Parameter()][switch]$SelfTest,
    [Parameter()][switch]$ShowContext,
    [Parameter()][switch]$ListOperations,
    [Parameter()][switch]$ShowOperationDetails,
    [Parameter()][switch]$ShowBundledModuleVersions,
    [Parameter()][switch]$ShowResolvedModuleVersions,
    [Parameter()][switch]$ToolVersion
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
    ScriptName                   = 'ArmClient-PS.ps1'
    ToolName                     = 'ArmClient-PS'
    Version                      = '1.0.1'
    Author                       = 'Blake Drumm (blakedrumm@microsoft.com)'
    RequiredRootModules          = @('Az.Accounts')
    SupportedBuiltInEnvironments = @('AzureCloud','AzureUSGovernment','AzureChinaCloud','AzureUSNat','AzureUSSec')
    DeprecatedEnvironments       = @('AzureGermanCloud')
    DefaultJsonDepth             = 100
    DefaultPollIntervalSeconds   = 5
    LongRunningTimeoutSeconds    = 1800
    ManifestDirectoryName        = 'Manifest'
    ModulesDirectoryName         = 'Modules'
    DefaultLogDirectoryName      = 'Logs'
    DefaultOutputDirectoryName   = 'Output'
    ProviderMetadataApiVersion   = '2021-04-01'
    FileHashManifestName         = 'Files.sha256.json'
    VersionsManifestName         = 'Versions.json'
    DangerousHeaders             = @('Authorization','Proxy-Authorization','Cookie','Set-Cookie','Content-Length','Host','Connection','Transfer-Encoding')
    AllowedSignatureExtensions   = @('.ps1','.psm1','.psd1')
    TextFileExtensions           = @('.ps1','.psm1','.psd1','.ps1xml','.json','.txt','.xml')
    AllowedBodyMethods           = @('POST','PUT','PATCH')
    CorrelationHeaderNames       = @('x-ms-correlation-request-id','x-ms-client-request-id','x-ms-routing-request-id')
    RequestHeaderNames           = @('x-ms-request-id','x-ms-arm-service-request-id','x-ms-service-request-id')
}

$script:ScriptPath = if ($PSCommandPath) { $PSCommandPath } elseif ($MyInvocation.MyCommand.Path) { $MyInvocation.MyCommand.Path } else { Join-Path (Get-Location).Path $script:Configuration.ScriptName }
$script:SessionState = [ordered]@{
    ScriptRoot             = $null
    ModulesPath            = $null
    ManifestPath           = $null
    LogsPath               = $null
    OutputPath             = $null
    LogFilePath            = $null
    FileHashManifest       = $null
    VersionsManifest       = $null
    ProviderMetadataCache  = @{}
    DebugEnabled           = [bool]$DebugLogging
    AuthenticatedByScript  = $false
    ShouldClearContext     = [bool]$ClearContextOnExit
    SelectedEnvironment    = $Environment
    ResolvedModules        = @()
    BundledModulePathAdded = $false
}
$script:SessionState['BoundParameterNames'] = @($PSBoundParameters.Keys)

# General helpers used by the rest of the script for path safety, directory
# creation, and log output.
function Get-ScriptRoot { [CmdletBinding()] param() (Split-Path -Path $script:ScriptPath -Parent) }
function Ensure-Directory { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Path) if (-not (Test-Path -LiteralPath $Path)) { $null = New-Item -Path $Path -ItemType Directory -Force } }
function ConvertTo-NormalizedRelativePath { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Path) $Path.Replace('/','\').TrimStart('.').TrimStart('\').ToLowerInvariant() }
function Get-RelativePathFromRoot { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$FullPath) $root=[IO.Path]::GetFullPath($script:SessionState.ScriptRoot); $path=[IO.Path]::GetFullPath($FullPath); if(-not $path.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)){ throw "Path '$FullPath' is outside of script root '$root'." }; $path.Substring($root.Length).TrimStart('\','/') }
function Get-HashtableValueIgnoreCase { [CmdletBinding()] param([AllowNull()][Collections.IDictionary]$Table,[Parameter(Mandatory=$true)][string]$Key) if($null -eq $Table){return $null}; foreach($entryKey in $Table.Keys){ if([string]::Equals([string]$entryKey,$Key,[StringComparison]::OrdinalIgnoreCase)){ return $Table[$entryKey] } }; $null }
function Get-RequestedSubscriptionIdSafe { [CmdletBinding()] param() if($SubscriptionId){ return $SubscriptionId }; $requested = Get-HashtableValueIgnoreCase -Table $OperationParameters -Key 'subscriptionId'; if($requested){ return [string]$requested }; $null }

function Redact-SensitiveText {
    [CmdletBinding()] param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    # Match common credential/token shapes across plain text, JSON, and error
    # messages so logs stay useful without exposing secrets.
    $patterns = @(
        '(?i)(Authorization\s*[:=]\s*)(Bearer\s+)?[^\r\n;]+',
        '(?i)("?(authorization|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|secret|password|assertion|cookie|set-cookie)"?\s*[:=]\s*")[^"]+(")',
        '(?i)("?(authorization|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|secret|password|assertion|cookie|set-cookie)"?\s*[:=]\s*)[^,}\]\r\n]+'
    )
    $redacted = $Text
    foreach ($pattern in $patterns) {
        $redacted = [regex]::Replace($redacted,$pattern,{ param($m) $v=$m.Value; $i=$v.IndexOf(':'); if($i -lt 0){$i=$v.IndexOf('=')}; if($i -gt -1){ $v.Substring(0,$i+1)+' [REDACTED]' } else { '[REDACTED]' } })
    }
    [regex]::Replace($redacted,'(?i)Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*','Bearer [REDACTED]')
}

function ConvertTo-LogSafeString {
    [CmdletBinding()] param([AllowNull()][object]$InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string]) { return (Redact-SensitiveText -Text $InputObject) }
    try { Redact-SensitiveText -Text ($InputObject | ConvertTo-Json -Depth $script:Configuration.DefaultJsonDepth -Compress) }
    catch { Redact-SensitiveText -Text ($InputObject | Out-String) }
}

function Write-Log {
    [CmdletBinding()] param(
        [Parameter(Mandatory=$true)][ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level,
        [Parameter(Mandatory=$true)][string]$Message,
        [AllowNull()][object]$Data
    )
    if ($Level -eq 'DEBUG' -and -not $script:SessionState.DebugEnabled) { return }
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffK'), $Level, (Redact-SensitiveText -Text $Message)
    if ($PSBoundParameters.ContainsKey('Data')) { $safe = ConvertTo-LogSafeString -InputObject $Data; if (-not [string]::IsNullOrWhiteSpace($safe)) { $line = '{0} | {1}' -f $line, $safe } }
    if ($script:SessionState.LogFilePath) { Add-Content -LiteralPath $script:SessionState.LogFilePath -Value $line -Encoding UTF8 }
    Write-Host $line
}

function Get-LastPipelineValueSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [object[]]$Values
    )

    $nonStringValues = @($Values | Where-Object { $_ -isnot [string] })
    if ($nonStringValues.Count -gt 0) {
        return $nonStringValues[-1]
    }

    if ($Values.Count -gt 0) {
        return $Values[-1]
    }

    return $null
}
function Get-FileHashManifestSafe {
    [CmdletBinding()] param()
    if ($null -eq $script:SessionState.FileHashManifest) {
        $path = Join-Path $script:SessionState.ManifestPath $script:Configuration.FileHashManifestName
        if (-not (Test-Path -LiteralPath $path)) { throw "Required manifest file '$path' was not found. Run Build-BundledModules.ps1 on a maintainer machine and redistribute the completed package." }
        $script:SessionState.FileHashManifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    }
    $script:SessionState.FileHashManifest
}

function Get-VersionsManifestSafe {
    [CmdletBinding()] param()
    if ($null -eq $script:SessionState.VersionsManifest) {
        $path = Join-Path $script:SessionState.ManifestPath $script:Configuration.VersionsManifestName
        if (Test-Path -LiteralPath $path) { $script:SessionState.VersionsManifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json }
    }
    $script:SessionState.VersionsManifest
}

function Get-NormalizedFileHash {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$LiteralPath, [string]$Algorithm = 'SHA256')
    $ext = [IO.Path]::GetExtension($LiteralPath).ToLowerInvariant()
    if ($script:Configuration.TextFileExtensions -contains $ext) {
        # Normalize line endings before hashing text files so the same packaged
        # content produces the same manifest hash on Windows and non-Windows hosts.
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

function Test-FileHashManifest {
    [CmdletBinding()] param([string[]]$RelativePaths)
    if ($SkipHashValidation) { Write-Log -Level 'WARN' -Message 'Hash validation was skipped because -SkipHashValidation was supplied.'; return }
    $manifest = Get-FileHashManifestSafe
    $entries = @($manifest.files)
    if ($RelativePaths) {
        $filter = $RelativePaths | ForEach-Object { ConvertTo-NormalizedRelativePath -Path $_ }
        $entries = $entries | Where-Object { (ConvertTo-NormalizedRelativePath -Path $_.path) -in $filter }
    }
    if ($entries.Count -lt 1) { throw 'File hash manifest does not contain the required package entries. Rebuild the package with Build-BundledModules.ps1 before distribution.' }
    foreach ($entry in $entries) {
        $fullPath = Join-Path $script:SessionState.ScriptRoot ([string]$entry.path)
        if (-not (Test-Path -LiteralPath $fullPath)) { throw "Hash validation failed because '$($entry.path)' is missing. The package is incomplete or was modified after packaging." }
        $hashAlgorithm = if ($entry.algorithm) { [string]$entry.algorithm } else { 'SHA256' }
        $actual = Get-NormalizedFileHash -LiteralPath $fullPath -Algorithm $hashAlgorithm
        $expected = ([string]$entry.hash).ToUpperInvariant()
        if ($actual -ne $expected) { throw "Hash validation failed for '$($entry.path)'. The package contents no longer match the trusted manifest. Rebuild or replace the package before continuing." }
    }
    Write-Log -Level 'INFO' -Message ('Validated {0} file hash entries.' -f $entries.Count)
}

function Get-SignableFiles {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Leaf) { return ,$Path }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return @() }
    @(Get-ChildItem -LiteralPath $Path -Recurse -File | Where-Object { $script:Configuration.AllowedSignatureExtensions -contains $_.Extension.ToLowerInvariant() } | ForEach-Object { $_.FullName })
}

function Test-AuthenticodeIfRequested {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string[]]$Paths)
    if (-not $EnforceSignatureValidation) { return }
    foreach ($path in ($Paths | Sort-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $path)) { throw "Signature validation failed because '$path' does not exist." }
        if ($script:Configuration.AllowedSignatureExtensions -notcontains ([IO.Path]::GetExtension($path).ToLowerInvariant())) { continue }
        $signature = Get-AuthenticodeSignature -FilePath $path
        if ($signature.Status -ne 'Valid') { throw "Signature validation failed for '$path'. Status: $($signature.Status)." }
    }
    Write-Log -Level 'INFO' -Message ('Validated Authenticode signatures for {0} file(s).' -f $Paths.Count)
}

function Test-BundledModuleFiles {
    [CmdletBinding()] param()
    # Validate the script, build manifest, and all bundled module files before
    # any imports occur so package tampering is detected early.
    $paths = [Collections.Generic.List[string]]::new()
    $paths.Add($script:Configuration.ScriptName)
    $paths.Add('Build-BundledModules.ps1')
    $paths.Add((Join-Path $script:Configuration.ManifestDirectoryName $script:Configuration.VersionsManifestName))
    foreach ($entry in @((Get-FileHashManifestSafe).files)) {
        $relativePath = [string]$entry.path
        if ((ConvertTo-NormalizedRelativePath -Path $relativePath).StartsWith((ConvertTo-NormalizedRelativePath -Path $script:Configuration.ModulesDirectoryName))) { $paths.Add($relativePath) }
    }
    Test-FileHashManifest -RelativePaths ($paths.ToArray())
}

function Import-ModuleManifestDataSafe { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$ManifestPath) try { Import-PowerShellDataFile -Path $ManifestPath } catch { Write-Log -Level 'WARN' -Message "Unable to parse module manifest '$ManifestPath'." -Data $_.Exception.Message; $null } }
function Get-ManifestValueSafe { [CmdletBinding()] param([Parameter(Mandatory=$true)][object]$ManifestData,[Parameter(Mandatory=$true)][string]$Name) if($ManifestData -is [Collections.IDictionary]){ if($ManifestData.Contains($Name)){ $ManifestData[$Name] } else { $null } } else { $property=$ManifestData.PSObject.Properties[$Name]; if($property){ $property.Value } else { $null } } }
function ConvertTo-VersionSafe { [CmdletBinding()] param([AllowNull()][object]$Value) if($null -eq $Value){return [version]'0.0.0.0'}; try {[version]($Value.ToString())} catch { $parts=($Value.ToString() -split '[^0-9]+' | ? { $_ }); while($parts.Count -lt 4){ $parts += '0' }; [version]($parts[0..3] -join '.') } }

function New-ModuleInfoObject {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Name,[Parameter(Mandatory=$true)][string]$ManifestPath,[Parameter(Mandatory=$true)][string]$ModuleBase,[Parameter(Mandatory=$true)][string]$Source)
    $manifestData = Import-ModuleManifestDataSafe -ManifestPath $ManifestPath
    if ($null -eq $manifestData) { return $null }
    $moduleVersion = Get-ManifestValueSafe -ManifestData $manifestData -Name 'ModuleVersion'
    # PowerShell manifests can express RequiredModules in multiple shapes. This
    # block normalizes them into a simple list of dependency names.
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
    [pscustomobject]@{
        Name              = $Name
        Version           = [string]$moduleVersion
        VersionNormalized = ConvertTo-VersionSafe -Value $moduleVersion
        ManifestPath      = [IO.Path]::GetFullPath($ManifestPath)
        ModuleBase        = [IO.Path]::GetFullPath($ModuleBase)
        Source            = $Source
        RequiredModules   = @($requiredModules | ? { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        Guid              = [string](Get-ManifestValueSafe -ManifestData $manifestData -Name 'GUID')
    }
}

function Get-InstalledModuleInfoSafe {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$ModuleName)
    $bundledRoot = [IO.Path]::GetFullPath($script:SessionState.ModulesPath)
    $moduleEntries = @(Get-Module -ListAvailable -Name $ModuleName | ? { $_.Path -and -not ([IO.Path]::GetFullPath($_.ModuleBase).StartsWith($bundledRoot,[StringComparison]::OrdinalIgnoreCase)) })
    $items = foreach ($moduleEntry in $moduleEntries) {
        $manifestPath = if ($moduleEntry.Path -and $moduleEntry.Path.ToLowerInvariant().EndsWith('.psd1')) { $moduleEntry.Path } else { Join-Path $moduleEntry.ModuleBase ($ModuleName + '.psd1') }
        if (Test-Path -LiteralPath $manifestPath) { New-ModuleInfoObject -Name $ModuleName -ManifestPath $manifestPath -ModuleBase $moduleEntry.ModuleBase -Source 'Installed' }
    }
    @($items | ? { $null -ne $_ } | Sort-Object VersionNormalized -Descending)
}

function Get-BundledModuleInfoSafe {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$ModuleName)
    $moduleFolder = Join-Path $script:SessionState.ModulesPath $ModuleName
    if (-not (Test-Path -LiteralPath $moduleFolder -PathType Container)) { return @() }
    $items = foreach ($manifestFile in @(Get-ChildItem -LiteralPath $moduleFolder -Recurse -Filter ($ModuleName + '.psd1') -File)) { New-ModuleInfoObject -Name $ModuleName -ManifestPath $manifestFile.FullName -ModuleBase $manifestFile.Directory.FullName -Source 'Bundled' }
    @($items | ? { $null -ne $_ } | Sort-Object VersionNormalized -Descending)
}

function Resolve-PreferredModuleVersion {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$ModuleName)
    $bundled = Get-BundledModuleInfoSafe -ModuleName $ModuleName | Select-Object -First 1
    $installed = Get-InstalledModuleInfoSafe -ModuleName $ModuleName | Select-Object -First 1
    # Auto mode prefers the newer available module while still allowing callers
    # to force bundled-only or installed-preferred behavior explicitly.
    $mode = if ($PreferBundledModules) { 'PreferBundled' } elseif ($PreferInstalledModules) { 'PreferInstalledWhenNewer' } else { 'Auto' }
    $preferred = $null; $fallback = $null
    if ($PreferBundledModules) { $preferred = $bundled; $fallback = $installed }
    elseif ($installed -and $bundled) { if ($installed.VersionNormalized -gt $bundled.VersionNormalized) { $preferred=$installed; $fallback=$bundled } else { $preferred=$bundled; $fallback=$installed } }
    elseif ($installed) { $preferred = $installed }
    elseif ($bundled) { $preferred = $bundled }
    if (-not $preferred) { throw "Module '$ModuleName' could not be resolved from bundled modules or installed modules. Verify the packaged Modules folder or install a valid local copy of the module." }
    [pscustomobject]@{ Name=$ModuleName; SelectionMode=$mode; BundledCandidate=$bundled; InstalledCandidate=$installed; PreferredCandidate=$preferred; FallbackCandidate=$fallback; SelectedCandidate=$null }
}

function Get-SelectedModuleDependencies { [CmdletBinding()] param([Parameter(Mandatory=$true)][pscustomobject]$ResolutionItem) $candidate = if($ResolutionItem.SelectedCandidate){$ResolutionItem.SelectedCandidate}else{$ResolutionItem.PreferredCandidate}; if($null -eq $candidate){@()} else {@($candidate.RequiredModules)} }
function Add-ResolvedModuleToTable { [CmdletBinding()] param([Parameter(Mandatory=$true)][hashtable]$Table,[Parameter(Mandatory=$true)][string]$ModuleName) if($Table.ContainsKey($ModuleName)){return}; $resolution=Resolve-PreferredModuleVersion -ModuleName $ModuleName; $Table[$ModuleName]=$resolution; foreach($dependency in @(Get-SelectedModuleDependencies -ResolutionItem $resolution)){ Add-ResolvedModuleToTable -Table $Table -ModuleName $dependency } }
function Get-ResolvedModuleTable {
    [CmdletBinding()] param()
    $table = @{}
    $moduleNames = [Collections.Generic.List[string]]::new()
    foreach ($name in $script:Configuration.RequiredRootModules) { $moduleNames.Add($name) }
    $versionsManifest = Get-VersionsManifestSafe
    if ($versionsManifest -and $versionsManifest.modules) { foreach ($module in @($versionsManifest.modules)) { if ($module.name) { $moduleNames.Add([string]$module.name) } } }
    foreach ($moduleName in ($moduleNames | Sort-Object -Unique)) { Add-ResolvedModuleToTable -Table $table -ModuleName $moduleName }
    $ordered = [Collections.Generic.List[object]]::new(); $visit = @{}
    # Resolve dependencies depth-first so imports happen in dependency order and
    # circular references are surfaced with a clear error.
    function Visit-ModuleDependency { param([Parameter(Mandatory=$true)][string]$Name)
        if ($visit[$Name] -eq 'Visited') { return }
        if ($visit[$Name] -eq 'Visiting') { throw "Circular module dependency detected while resolving '$Name'." }
        $visit[$Name] = 'Visiting'; $item = $table[$Name]
        foreach ($dependency in @(Get-SelectedModuleDependencies -ResolutionItem $item)) { if (-not $table.ContainsKey($dependency)) { Add-ResolvedModuleToTable -Table $table -ModuleName $dependency }; Visit-ModuleDependency -Name $dependency }
        $visit[$Name] = 'Visited'; $ordered.Add($item)
    }
    foreach ($name in @($table.Keys | Sort-Object)) { Visit-ModuleDependency -Name $name }
    @($ordered)
}

function Add-BundledModulesToPsModulePath {
    [CmdletBinding()] param()
    if ($script:SessionState.BundledModulePathAdded) { return }
    $separator = [IO.Path]::PathSeparator
    $paths = $env:PSModulePath -split [regex]::Escape([string]$separator)
    if ($paths -notcontains $script:SessionState.ModulesPath) { $env:PSModulePath = $script:SessionState.ModulesPath + $separator + $env:PSModulePath }
    $script:SessionState.BundledModulePathAdded = $true
}

function Clear-ModuleZoneIdentifier {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$ModuleBase)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return }
    if (-not (Get-Command -Name Unblock-File -ErrorAction SilentlyContinue)) { return }
    $extensions = @('.ps1','.psm1','.psd1','.ps1xml','.dll','.exe','.json','.txt','.xml')
    foreach ($file in @(Get-ChildItem -LiteralPath $ModuleBase -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $extensions -contains $_.Extension.ToLowerInvariant() })) {
        try { Unblock-File -LiteralPath $file.FullName -ErrorAction Stop }
        catch { Write-Log -Level 'DEBUG' -Message "Could not remove Zone.Identifier metadata from '$($file.FullName)'; continuing with module import." -Data $_.Exception.Message }
    }
}

function Import-ResolvedModule {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][pscustomobject]$ResolutionItem)
    # Try the preferred candidate first and only fall back if that import fails.
    $queue = [Collections.Generic.List[object]]::new(); if ($ResolutionItem.PreferredCandidate) { $queue.Add($ResolutionItem.PreferredCandidate) }; if ($ResolutionItem.FallbackCandidate -and ($ResolutionItem.PreferredCandidate -eq $null -or $ResolutionItem.FallbackCandidate.ManifestPath -ne $ResolutionItem.PreferredCandidate.ManifestPath)) { $queue.Add($ResolutionItem.FallbackCandidate) }
    foreach ($candidate in $queue) {
        try {
            $loaded = Get-Module -Name $candidate.Name | Sort-Object Version -Descending | Select-Object -First 1
            if ($loaded) {
                if ($loaded.Version.ToString() -eq $candidate.Version -and ([IO.Path]::GetFullPath($loaded.ModuleBase) -eq $candidate.ModuleBase)) { $ResolutionItem.SelectedCandidate=$candidate; Write-Log -Level 'DEBUG' -Message "Module '$($candidate.Name)' is already loaded from '$($candidate.ModuleBase)'."; return $ResolutionItem }
                throw "Module '$($candidate.Name)' is already loaded from '$($loaded.ModuleBase)' version '$($loaded.Version)'. Start a new PowerShell session or use a consistent module selection mode before running the tool again."
            }
            if ($candidate.Source -eq 'Bundled') {
                Add-BundledModulesToPsModulePath
                if (-not $SkipHashValidation) {
                    # Re-validate just the selected module subtree immediately
                    # before import to reduce the chance of a tampered module loading.
                    $moduleRelativeRoot = Get-RelativePathFromRoot -FullPath $candidate.ModuleBase
                    $moduleEntries = @((Get-FileHashManifestSafe).files | ? { (ConvertTo-NormalizedRelativePath -Path $_.path).StartsWith((ConvertTo-NormalizedRelativePath -Path $moduleRelativeRoot)) })
                    if ($moduleEntries.Count -lt 1) { throw "Bundled module '$($candidate.Name)' was selected from '$moduleRelativeRoot' but no matching hash manifest entries were found. Rebuild the package manifests before distribution." }
                    Test-FileHashManifest -RelativePaths ($moduleEntries | % { [string]$_.path })
                }
            }
            Clear-ModuleZoneIdentifier -ModuleBase $candidate.ModuleBase
            if ($EnforceSignatureValidation) { $signable = Get-SignableFiles -Path $candidate.ModuleBase; if ($signable.Count -lt 1) { throw "Signature validation was requested, but no signable files were found for module '$($candidate.Name)'." }; Test-AuthenticodeIfRequested -Paths $signable }
            Import-Module -Name $candidate.ManifestPath -Force -DisableNameChecking -Scope Global -WarningAction SilentlyContinue | Out-Null
            $ResolutionItem.SelectedCandidate = $candidate
            Write-Log -Level 'INFO' -Message ('Selected module {0} {1} from {2}.' -f $candidate.Name,$candidate.Version,$candidate.ModuleBase)
            return $ResolutionItem
        }
        catch { Write-Log -Level 'WARN' -Message "Module import attempt failed for '$($candidate.Name)' from '$($candidate.ModuleBase)'." -Data $_.Exception.Message }
    }
    throw "Unable to import module '$($ResolutionItem.Name)' from any resolved source."
}

function Import-BundledModules { [CmdletBinding()] param() Test-BundledModuleFiles; $resolved = Get-ResolvedModuleTable; $imported = foreach($item in $resolved){ Get-LastPipelineValueSafe -Values @(Import-ResolvedModule -ResolutionItem $item) }; $script:SessionState.ResolvedModules = @($imported | Where-Object { $null -ne $_ }); $script:SessionState.ResolvedModules }

# Authentication helpers. These functions validate identifiers, establish the
# process-scoped Az context, and recover interactively when tenant or
# subscription selection cannot be resolved automatically.
function Test-TenantIdentifier { [CmdletBinding()] param([string]$Value) if([string]::IsNullOrWhiteSpace($Value)){return $true}; if($Value -match '^[0-9a-fA-F-]{36}$'){return $true}; ($Value -match '^[A-Za-z0-9][A-Za-z0-9\.-]*\.[A-Za-z]{2,}$') }
function Test-SubscriptionIdentifier { [CmdletBinding()] param([string]$Value) if([string]::IsNullOrWhiteSpace($Value)){return $true}; ($Value -match '^[0-9a-fA-F-]{36}$') }
function Test-SubscriptionErrorMessage { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Message) ($Message -like '*does not have access to subscription*') -or ($Message -like '*could not be found*' -and $Message -like '*subscription*') }
function Test-TenantErrorMessage { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Message) ($Message -like '*Unable to acquire token for tenant*') -or ($Message -like '*User interaction is required*' -and $Message -like '*tenant*') -or ($Message -like '*multiple tenants*') -or ($Message -like '*AADSTS50076*') -or ($Message -like '*tenant*' -and $Message -like '*MFA*') }

function Get-CurrentAzContextSafe {
    [CmdletBinding()] param()
    try { $context = Get-AzContext -ErrorAction Stop } catch { return $null }
    if ($null -eq $context) { return $null }
    [pscustomobject]@{ Account=if($context.Account){[string]$context.Account.Id}else{$null}; TenantId=if($context.Tenant){[string]$context.Tenant.Id}else{$null}; SubscriptionId=if($context.Subscription){[string]$context.Subscription.Id}else{$null}; SubscriptionName=if($context.Subscription){[string]$context.Subscription.Name}else{$null}; Environment=if($context.Environment){[string]$context.Environment.Name}else{$null} }
}

function Initialize-AzProcessSecurity { [CmdletBinding()] param() Disable-AzContextAutosave -Scope Process -WarningAction SilentlyContinue | Out-Null; Write-Log -Level 'INFO' -Message 'Disabled Az context autosave for the current process.' }
function Get-AzEnvironmentSafe { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Name) try { Get-AzEnvironment -Name $Name -ErrorAction Stop } catch { $null } }
function Set-TargetSubscription { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$TargetSubscriptionId) if(-not (Test-SubscriptionIdentifier -Value $TargetSubscriptionId)){ throw "SubscriptionId '$TargetSubscriptionId' is not a valid GUID." }; $null = Set-AzContext -Subscription $TargetSubscriptionId -ErrorAction Stop; Write-Log -Level 'INFO' -Message "Set Azure context subscription to '$TargetSubscriptionId'." }

function Select-AzTenantInteractive {
    [CmdletBinding()] param()
    Write-Log -Level 'INFO' -Message 'Multiple tenants available. Retrieving tenant list...'
    $tenants = @(Get-AzTenant -ErrorAction Stop)
    if ($tenants.Count -eq 0) {
        throw 'No tenants found for the authenticated account.'
    }
    if ($tenants.Count -eq 1) {
        Write-Log -Level 'INFO' -Message "Only one tenant available: '$($tenants[0].Id)'. Selecting it automatically."
        return $tenants[0].Id
    }
    Write-Host ''
    Write-Host 'Available tenants:' -ForegroundColor Cyan
    Write-Host ('-' * 80) -ForegroundColor DarkGray
    for ($i = 0; $i -lt $tenants.Count; $i++) {
        $t = $tenants[$i]
        $index = $i + 1
        $displayId = $t.Id
        $displayName = $t.Name
        $defaultDomain = $t.DefaultDomain
        $label = if ($displayName) { $displayName } else { $displayId }
        Write-Host ('  [{0}] {1}' -f $index, $label) -ForegroundColor White -NoNewline
        if ($displayName -and $defaultDomain) {
            Write-Host (' ({0} - {1})' -f $displayId, $defaultDomain) -ForegroundColor DarkGray
        }
        elseif ($displayName) {
            Write-Host (' ({0})' -f $displayId) -ForegroundColor DarkGray
        }
        else {
            Write-Host ''
        }
    }
    Write-Host ('-' * 80) -ForegroundColor DarkGray
    Write-Host ''
    while ($true) {
        $selection = Read-Host 'Enter the number of the tenant to use'
        if ([string]::IsNullOrWhiteSpace($selection)) { continue }
        $parsed = 0
        if ([int]::TryParse($selection, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le $tenants.Count) {
            $chosen = $tenants[$parsed - 1]
            $chosenLabel = if ($chosen.Name) { "'{0}' ({1})" -f $chosen.Name, $chosen.Id } else { $chosen.Id }
            Write-Log -Level 'INFO' -Message "Selected tenant: $chosenLabel."
            return $chosen.Id
        }
        Write-Host "Invalid selection '$selection'. Please enter a number between 1 and $($tenants.Count)." -ForegroundColor Red
    }
}

function Select-AzSubscriptionInteractive {
    [CmdletBinding()] param()
    Write-Log -Level 'INFO' -Message 'Multiple subscriptions available. Retrieving subscription list...'
    $subscriptions = @(Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' })
    if ($subscriptions.Count -eq 0) {
        $subscriptions = @(Get-AzSubscription -ErrorAction Stop)
    }
    if ($subscriptions.Count -eq 0) {
        throw 'No subscriptions found for the authenticated account.'
    }
    if ($subscriptions.Count -eq 1) {
        Write-Log -Level 'INFO' -Message "Only one subscription available: '$($subscriptions[0].Name)' ($($subscriptions[0].Id)). Selecting it automatically."
        return $subscriptions[0].Id
    }
    Write-Host ''
    Write-Host 'Available subscriptions:' -ForegroundColor Cyan
    Write-Host ('-' * 80) -ForegroundColor DarkGray
    for ($i = 0; $i -lt $subscriptions.Count; $i++) {
        $sub = $subscriptions[$i]
        $index = $i + 1
        $state = $sub.State
        $displayName = $sub.Name
        $displayId = $sub.Id
        Write-Host ('  [{0}] {1}' -f $index, $displayName) -ForegroundColor White -NoNewline
        Write-Host (' ({0})' -f $displayId) -ForegroundColor DarkGray -NoNewline
        if ($state -ne 'Enabled') {
            Write-Host (' [{0}]' -f $state) -ForegroundColor Yellow
        }
        else {
            Write-Host ''
        }
    }
    Write-Host ('-' * 80) -ForegroundColor DarkGray
    Write-Host ''
    while ($true) {
        $selection = Read-Host 'Enter the number of the subscription to use'
        if ([string]::IsNullOrWhiteSpace($selection)) { continue }
        $parsed = 0
        if ([int]::TryParse($selection, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le $subscriptions.Count) {
            $chosen = $subscriptions[$parsed - 1]
            Write-Log -Level 'INFO' -Message "Selected subscription: '$($chosen.Name)' ($($chosen.Id))."
            return $chosen.Id
        }
        Write-Host "Invalid selection '$selection'. Please enter a number between 1 and $($subscriptions.Count)." -ForegroundColor Red
    }
}

function Connect-ArmClientPs {
    [CmdletBinding()] param()
    $requestedSubscriptionId = Get-RequestedSubscriptionIdSafe
    if (-not (Test-TenantIdentifier -Value $TenantId)) { throw "TenantId '$TenantId' is not a valid GUID or verified domain name." }
    if (-not (Test-SubscriptionIdentifier -Value $requestedSubscriptionId)) { throw "SubscriptionId '$requestedSubscriptionId' is not a valid GUID." }
    $environmentObject = Get-AzEnvironmentSafe -Name $script:SessionState.SelectedEnvironment
    if ($null -eq $environmentObject) {
        if ($script:Configuration.DeprecatedEnvironments -contains $script:SessionState.SelectedEnvironment) { throw "Azure environment '$($script:SessionState.SelectedEnvironment)' is deprecated and is not available in the resolved Az.Accounts runtime on this machine. Choose another environment or update the bundled module set." }
        $availableNames = @(try { Get-AzEnvironment -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } } catch { @() })
        $hint = if ($availableNames.Count -gt 0) { "Available environments on this machine: $($availableNames -join ', ')." } else { "Built-in defaults include $($script:Configuration.SupportedBuiltInEnvironments -join ', '). Custom or Azure Stack environments can be registered with Add-AzEnvironment." }
        throw "Azure environment '$($script:SessionState.SelectedEnvironment)' is not available. $hint"
    }
    Write-Log -Level 'INFO' -Message "Using Azure environment '$($environmentObject.Name)'."
    if ($NoLogin) {
        # In -NoLogin mode the script is allowed to reuse an existing context,
        # but it must not start a new authentication flow.
        $existingContext = Get-CurrentAzContextSafe
        if ($null -eq $existingContext) { throw 'No usable Azure context exists in the current process and -NoLogin was supplied. Remove -NoLogin or sign in first in this session.' }
        if ($requestedSubscriptionId -and $existingContext.SubscriptionId -ne $requestedSubscriptionId) { Set-TargetSubscription -TargetSubscriptionId $requestedSubscriptionId; $existingContext = Get-CurrentAzContextSafe }
        return $existingContext
    }
    $connectParams = @{ Environment=$environmentObject.Name; Scope='Process'; ErrorAction='Stop'; SkipContextPopulation=$true; MaxContextPopulation=1 }
    if ($TenantId) { $connectParams['Tenant'] = $TenantId }
    if ($requestedSubscriptionId) { $connectParams['Subscription'] = $requestedSubscriptionId }
    if ($UseManagedIdentity) { $connectParams['Identity'] = $true } elseif ($UseDeviceCode) { $connectParams['UseDeviceAuthentication'] = $true }
    try {
        $null = Connect-AzAccount @connectParams
    }
    catch {
        $errMsg = $_.Exception.Message
        $isSubscriptionError = Test-SubscriptionErrorMessage -Message $errMsg
        $isTenantError = Test-TenantErrorMessage -Message $errMsg
        if (-not $isSubscriptionError -and -not $isTenantError) { throw }
        if ($isTenantError) {
            # First connect broadly, then let the user choose a tenant once the
            # account's available tenants are known to the current session.
            Write-Log -Level 'WARN' -Message 'Tenant could not be resolved automatically. Attempting to authenticate and list available tenants.'
            $tenantFallbackParams = @{ Environment=$environmentObject.Name; Scope='Process'; ErrorAction='Stop' }
            if ($UseManagedIdentity) { $tenantFallbackParams['Identity'] = $true } elseif ($UseDeviceCode) { $tenantFallbackParams['UseDeviceAuthentication'] = $true }
            $null = Connect-AzAccount @tenantFallbackParams
            $selectedTenantId = Select-AzTenantInteractive
            $tenantReconnectParams = @{ Environment=$environmentObject.Name; Scope='Process'; ErrorAction='Stop'; Tenant=$selectedTenantId }
            if ($requestedSubscriptionId) { $tenantReconnectParams['Subscription'] = $requestedSubscriptionId }
            if ($UseManagedIdentity) { $tenantReconnectParams['Identity'] = $true } elseif ($UseDeviceCode) { $tenantReconnectParams['UseDeviceAuthentication'] = $true }
            try {
                $null = Connect-AzAccount @tenantReconnectParams
            }
            catch {
                $reconnectErr = $_.Exception.Message
                $isSubErrorAfterTenant = Test-SubscriptionErrorMessage -Message $reconnectErr
                if (-not $isSubErrorAfterTenant) { throw }
                $subFallback = @{ Environment=$environmentObject.Name; Scope='Process'; ErrorAction='Stop'; Tenant=$selectedTenantId }
                if ($UseManagedIdentity) { $subFallback['Identity'] = $true } elseif ($UseDeviceCode) { $subFallback['UseDeviceAuthentication'] = $true }
                $null = Connect-AzAccount @subFallback
                $selectedSubId = Select-AzSubscriptionInteractive
                Set-TargetSubscription -TargetSubscriptionId $selectedSubId
            }
        }
        else {
            # Use the same recovery pattern for subscription issues: connect
            # first, then prompt the user with the available subscriptions.
            Write-Log -Level 'WARN' -Message 'Subscription could not be resolved. Attempting to authenticate without a specific subscription and list available subscriptions.'
            $fallbackParams = @{ Environment=$environmentObject.Name; Scope='Process'; ErrorAction='Stop' }
            if ($TenantId) { $fallbackParams['Tenant'] = $TenantId }
            if ($UseManagedIdentity) { $fallbackParams['Identity'] = $true } elseif ($UseDeviceCode) { $fallbackParams['UseDeviceAuthentication'] = $true }
            $null = Connect-AzAccount @fallbackParams
            $selectedSubId = Select-AzSubscriptionInteractive
            Set-TargetSubscription -TargetSubscriptionId $selectedSubId
        }
    }
    $script:SessionState.AuthenticatedByScript = $true
    if ($requestedSubscriptionId) {
        $ctx = Get-CurrentAzContextSafe
        if ($null -eq $ctx -or $ctx.SubscriptionId -ne $requestedSubscriptionId) { Set-TargetSubscription -TargetSubscriptionId $requestedSubscriptionId }
    }
    $currentContext = Get-CurrentAzContextSafe
    if ($null -eq $currentContext) { throw 'Authentication completed but no Azure context is available. Re-run the command and confirm that the selected account can access the requested tenant or subscription.' }
    Write-Log -Level 'INFO' -Message 'Authenticated Azure context.' -Data $currentContext
    $currentContext
}

function New-ArmOperationPreset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Category,
        [Parameter(Mandatory=$true)][string]$Description,
        [Parameter(Mandatory=$true)][ValidateSet('GET','POST','PUT','PATCH','DELETE')][string]$Method,
        [Parameter(Mandatory=$true)][string]$RelativePathTemplate,
        [Parameter(Mandatory=$true)][string]$DefaultApiVersion,
        [string[]]$Aliases,
        [string]$ProviderNamespace,
        [string]$ResourceType,
        [string[]]$RequiredParameters,
        [string[]]$OptionalParameters,
        [AllowNull()][object]$DefaultBodyTemplate,
        [string[]]$KnownApiVersions,
        [AllowNull()][hashtable]$ExampleParameters,
        [AllowNull()][object]$ExampleBody,
        [AllowNull()][string[]]$Notes
    )
    [pscustomobject]@{
        Name                 = $Name
        Category             = $Category
        Description          = $Description
        Method               = $Method
        RelativePathTemplate = $RelativePathTemplate
        DefaultApiVersion    = $DefaultApiVersion
        Aliases              = @($Aliases | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        ProviderNamespace    = $ProviderNamespace
        ResourceType         = $ResourceType
        RequiredParameters   = @($RequiredParameters | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        OptionalParameters   = @($OptionalParameters | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        DefaultBodyTemplate  = $DefaultBodyTemplate
        KnownApiVersions     = @($KnownApiVersions | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        ExampleParameters    = $ExampleParameters
        ExampleBody          = $ExampleBody
        Notes                = @($Notes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
}

function Get-ArmOperationPresetCatalog {
    [CmdletBinding()] param()
    @(
        New-ArmOperationPreset -Name 'ArmProvidersList' -Category 'ARM.Core' -Description 'List resource providers available to the current account.' -Method 'GET' -RelativePathTemplate '/providers' -DefaultApiVersion '2021-04-01' -Aliases @('providers','list-providers') -KnownApiVersions @('2021-04-01') -Notes @('Useful for discovering provider namespaces before selecting a more specific operation preset.')
        New-ArmOperationPreset -Name 'ArmProviderGet' -Category 'ARM.Core' -Description 'Get metadata for a single resource provider.' -Method 'GET' -RelativePathTemplate '/providers/{providerNamespace}' -DefaultApiVersion '2021-04-01' -Aliases @('provider','get-provider') -RequiredParameters @('providerNamespace') -ExampleParameters @{ providerNamespace='Microsoft.Communication' } -KnownApiVersions @('2021-04-01')
        New-ArmOperationPreset -Name 'ArmSubscriptionGet' -Category 'ARM.Core' -Description 'Get the current or specified subscription resource.' -Method 'GET' -RelativePathTemplate '/subscriptions/{subscriptionId}' -DefaultApiVersion '2022-12-01' -Aliases @('subscription','get-subscription') -RequiredParameters @('subscriptionId') -ExampleParameters @{ subscriptionId='<subscription-id>' } -KnownApiVersions @('2022-12-01')
        New-ArmOperationPreset -Name 'ArmResourceGroupList' -Category 'ARM.Resources' -Description 'List resource groups in a subscription.' -Method 'GET' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups' -DefaultApiVersion '2021-04-01' -Aliases @('resource-groups','list-resource-groups') -ProviderNamespace 'Microsoft.Resources' -ResourceType 'resourceGroups' -RequiredParameters @('subscriptionId') -ExampleParameters @{ subscriptionId='<subscription-id>' } -KnownApiVersions @('2021-04-01')
        New-ArmOperationPreset -Name 'ArmResourceGroupGet' -Category 'ARM.Resources' -Description 'Get a specific resource group.' -Method 'GET' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}' -DefaultApiVersion '2021-04-01' -Aliases @('resource-group','get-resource-group') -ProviderNamespace 'Microsoft.Resources' -ResourceType 'resourceGroups' -RequiredParameters @('subscriptionId','resourceGroupName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example' } -KnownApiVersions @('2021-04-01')
        New-ArmOperationPreset -Name 'ArmResourceGroupCreateOrUpdate' -Category 'ARM.Resources' -Description 'Create or update a resource group. Supply a JSON body with location and optional tags.' -Method 'PUT' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}' -DefaultApiVersion '2021-04-01' -Aliases @('new-resource-group','set-resource-group') -ProviderNamespace 'Microsoft.Resources' -ResourceType 'resourceGroups' -RequiredParameters @('subscriptionId','resourceGroupName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example' } -ExampleBody @{ location='eastus'; tags=@{ environment='dev' } } -KnownApiVersions @('2021-04-01')
        New-ArmOperationPreset -Name 'ArmResourceGroupDelete' -Category 'ARM.Resources' -Description 'Delete a resource group.' -Method 'DELETE' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}' -DefaultApiVersion '2021-04-01' -Aliases @('remove-resource-group','delete-resource-group') -ProviderNamespace 'Microsoft.Resources' -ResourceType 'resourceGroups' -RequiredParameters @('subscriptionId','resourceGroupName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example' } -KnownApiVersions @('2021-04-01')
        New-ArmOperationPreset -Name 'ArmResourcesListByResourceGroup' -Category 'ARM.Resources' -Description 'List resources contained in a resource group.' -Method 'GET' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/resources' -DefaultApiVersion '2021-04-01' -Aliases @('list-resources','resource-group-resources') -ProviderNamespace 'Microsoft.Resources' -ResourceType 'resources' -RequiredParameters @('subscriptionId','resourceGroupName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example' } -KnownApiVersions @('2021-04-01')
        New-ArmOperationPreset -Name 'ArmDeploymentListByResourceGroup' -Category 'ARM.Deployments' -Description 'List ARM deployments for a resource group.' -Method 'GET' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Resources/deployments' -DefaultApiVersion '2021-04-01' -Aliases @('list-deployments','resource-group-deployments') -ProviderNamespace 'Microsoft.Resources' -ResourceType 'deployments' -RequiredParameters @('subscriptionId','resourceGroupName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example' } -KnownApiVersions @('2021-04-01')
        New-ArmOperationPreset -Name 'ArmDeploymentGetByResourceGroup' -Category 'ARM.Deployments' -Description 'Get a specific ARM deployment in a resource group.' -Method 'GET' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Resources/deployments/{deploymentName}' -DefaultApiVersion '2021-04-01' -Aliases @('deployment','get-deployment') -ProviderNamespace 'Microsoft.Resources' -ResourceType 'deployments' -RequiredParameters @('subscriptionId','resourceGroupName','deploymentName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example'; deploymentName='main' } -KnownApiVersions @('2021-04-01')
        New-ArmOperationPreset -Name 'ArmDeploymentValidateByResourceGroup' -Category 'ARM.Deployments' -Description 'Validate a deployment payload at resource-group scope.' -Method 'POST' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Resources/deployments/{deploymentName}/validate' -DefaultApiVersion '2021-04-01' -Aliases @('validate-deployment') -ProviderNamespace 'Microsoft.Resources' -ResourceType 'deployments' -RequiredParameters @('subscriptionId','resourceGroupName','deploymentName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example'; deploymentName='main' } -KnownApiVersions @('2021-04-01') -Notes @('Supply a standard ARM deployment request body by using -Body or -BodyFile.')
        New-ArmOperationPreset -Name 'ArmDeploymentWhatIfByResourceGroup' -Category 'ARM.Deployments' -Description 'Run a what-if deployment preview at resource-group scope.' -Method 'POST' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Resources/deployments/{deploymentName}/whatIf' -DefaultApiVersion '2021-04-01' -Aliases @('whatif-deployment') -ProviderNamespace 'Microsoft.Resources' -ResourceType 'deployments' -RequiredParameters @('subscriptionId','resourceGroupName','deploymentName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example'; deploymentName='main' } -KnownApiVersions @('2021-04-01') -Notes @('Supply a standard ARM deployment request body by using -Body or -BodyFile.')
        New-ArmOperationPreset -Name 'ArmDeploymentCreateOrUpdateByResourceGroup' -Category 'ARM.Deployments' -Description 'Create or update a deployment at resource-group scope.' -Method 'PUT' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Resources/deployments/{deploymentName}' -DefaultApiVersion '2021-04-01' -Aliases @('set-deployment','new-deployment') -ProviderNamespace 'Microsoft.Resources' -ResourceType 'deployments' -RequiredParameters @('subscriptionId','resourceGroupName','deploymentName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example'; deploymentName='main' } -KnownApiVersions @('2021-04-01') -Notes @('Supply a standard ARM deployment request body by using -Body or -BodyFile.')
        New-ArmOperationPreset -Name 'ArmPolicyAssignmentsListAtSubscription' -Category 'ARM.Governance' -Description 'List policy assignments at subscription scope.' -Method 'GET' -RelativePathTemplate '/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyAssignments' -DefaultApiVersion '2024-04-01' -Aliases @('subscription-policy-assignments') -ProviderNamespace 'Microsoft.Authorization' -ResourceType 'policyAssignments' -RequiredParameters @('subscriptionId') -ExampleParameters @{ subscriptionId='<subscription-id>' } -KnownApiVersions @('2024-04-01','2022-06-01')
        New-ArmOperationPreset -Name 'ArmPolicyAssignmentsListAtResourceGroup' -Category 'ARM.Governance' -Description 'List policy assignments at resource-group scope.' -Method 'GET' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Authorization/policyAssignments' -DefaultApiVersion '2024-04-01' -Aliases @('resource-group-policy-assignments') -ProviderNamespace 'Microsoft.Authorization' -ResourceType 'policyAssignments' -RequiredParameters @('subscriptionId','resourceGroupName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example' } -KnownApiVersions @('2024-04-01','2022-06-01')
        New-ArmOperationPreset -Name 'ArmLocksListAtSubscription' -Category 'ARM.Governance' -Description 'List management locks at subscription scope.' -Method 'GET' -RelativePathTemplate '/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/locks' -DefaultApiVersion '2020-05-01' -Aliases @('subscription-locks') -ProviderNamespace 'Microsoft.Authorization' -ResourceType 'locks' -RequiredParameters @('subscriptionId') -ExampleParameters @{ subscriptionId='<subscription-id>' } -KnownApiVersions @('2020-05-01')
        New-ArmOperationPreset -Name 'ArmLocksListAtResourceGroup' -Category 'ARM.Governance' -Description 'List management locks at resource-group scope.' -Method 'GET' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Authorization/locks' -DefaultApiVersion '2020-05-01' -Aliases @('resource-group-locks') -ProviderNamespace 'Microsoft.Authorization' -ResourceType 'locks' -RequiredParameters @('subscriptionId','resourceGroupName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example' } -KnownApiVersions @('2020-05-01')
        New-ArmOperationPreset -Name 'AcsEmailServiceList' -Category 'ACS.Email' -Description 'List Email Communication Services in a resource group.' -Method 'GET' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Communication/emailServices' -DefaultApiVersion '2023-03-31' -Aliases @('acs-email-services','list-email-services') -ProviderNamespace 'Microsoft.Communication' -ResourceType 'emailServices' -RequiredParameters @('subscriptionId','resourceGroupName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example' } -KnownApiVersions @('2026-03-18','2025-09-01','2025-05-01','2025-05-01-preview','2024-09-01-preview','2023-06-01-preview','2023-04-01','2023-04-01-preview','2023-03-31','2023-03-01-preview','2022-07-01-preview','2021-10-01-preview')
        New-ArmOperationPreset -Name 'AcsEmailServiceGet' -Category 'ACS.Email' -Description 'Get a specific Email Communication Service.' -Method 'GET' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Communication/emailServices/{emailServiceName}' -DefaultApiVersion '2023-03-31' -Aliases @('acs-email-service','get-email-service') -ProviderNamespace 'Microsoft.Communication' -ResourceType 'emailServices' -RequiredParameters @('subscriptionId','resourceGroupName','emailServiceName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example'; emailServiceName='mailsvc1' } -KnownApiVersions @('2026-03-18','2025-09-01','2025-05-01','2025-05-01-preview','2024-09-01-preview','2023-06-01-preview','2023-04-01','2023-04-01-preview','2023-03-31','2023-03-01-preview','2022-07-01-preview','2021-10-01-preview')
        New-ArmOperationPreset -Name 'AcsEmailServiceCreateOrUpdate' -Category 'ACS.Email' -Description 'Create or update an Email Communication Service resource.' -Method 'PUT' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Communication/emailServices/{emailServiceName}' -DefaultApiVersion '2023-03-31' -Aliases @('new-email-service','set-email-service') -ProviderNamespace 'Microsoft.Communication' -ResourceType 'emailServices' -RequiredParameters @('subscriptionId','resourceGroupName','emailServiceName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example'; emailServiceName='mailsvc1' } -ExampleBody @{ location='global'; properties=@{ dataLocation='United States' } } -KnownApiVersions @('2026-03-18','2025-09-01','2025-05-01','2025-05-01-preview','2024-09-01-preview','2023-06-01-preview','2023-04-01','2023-04-01-preview','2023-03-31','2023-03-01-preview','2022-07-01-preview','2021-10-01-preview')
        New-ArmOperationPreset -Name 'AcsEmailServiceDelete' -Category 'ACS.Email' -Description 'Delete an Email Communication Service resource.' -Method 'DELETE' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Communication/emailServices/{emailServiceName}' -DefaultApiVersion '2023-03-31' -Aliases @('remove-email-service','delete-email-service') -ProviderNamespace 'Microsoft.Communication' -ResourceType 'emailServices' -RequiredParameters @('subscriptionId','resourceGroupName','emailServiceName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example'; emailServiceName='mailsvc1' } -KnownApiVersions @('2026-03-18','2025-09-01','2025-05-01','2025-05-01-preview','2024-09-01-preview','2023-06-01-preview','2023-04-01','2023-04-01-preview','2023-03-31','2023-03-01-preview','2022-07-01-preview','2021-10-01-preview')
        New-ArmOperationPreset -Name 'AcsEmailDomainList' -Category 'ACS.Email' -Description 'List email domains for an Email Communication Service.' -Method 'GET' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Communication/emailServices/{emailServiceName}/domains' -DefaultApiVersion '2023-03-31' -Aliases @('acs-email-domains','list-email-domains') -ProviderNamespace 'Microsoft.Communication' -ResourceType 'emailServices/domains' -RequiredParameters @('subscriptionId','resourceGroupName','emailServiceName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example'; emailServiceName='mailsvc1' } -KnownApiVersions @('2026-03-18','2025-09-01','2025-05-01','2025-05-01-preview','2024-09-01-preview','2023-06-01-preview','2023-04-01','2023-04-01-preview','2023-03-31','2023-03-01-preview','2022-07-01-preview','2021-10-01-preview')
        New-ArmOperationPreset -Name 'AcsEmailDomainGet' -Category 'ACS.Email' -Description 'Get a specific email domain resource.' -Method 'GET' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Communication/emailServices/{emailServiceName}/domains/{domainName}' -DefaultApiVersion '2023-03-31' -Aliases @('acs-email-domain','get-email-domain') -ProviderNamespace 'Microsoft.Communication' -ResourceType 'emailServices/domains' -RequiredParameters @('subscriptionId','resourceGroupName','emailServiceName','domainName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example'; emailServiceName='mailsvc1'; domainName='contoso.com' } -KnownApiVersions @('2026-03-18','2025-09-01','2025-05-01','2025-05-01-preview','2024-09-01-preview','2023-06-01-preview','2023-04-01','2023-04-01-preview','2023-03-31','2023-03-01-preview','2022-07-01-preview','2021-10-01-preview')
        New-ArmOperationPreset -Name 'AcsEmailDomainCreateOrUpdate' -Category 'ACS.Email' -Description 'Create or update an ACS email domain.' -Method 'PUT' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Communication/emailServices/{emailServiceName}/domains/{domainName}' -DefaultApiVersion '2023-03-31' -Aliases @('new-email-domain','set-email-domain') -ProviderNamespace 'Microsoft.Communication' -ResourceType 'emailServices/domains' -RequiredParameters @('subscriptionId','resourceGroupName','emailServiceName','domainName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example'; emailServiceName='mailsvc1'; domainName='contoso.com' } -ExampleBody @{ location='global'; properties=@{ domainManagement='CustomerManaged'; userEngagementTracking='Disabled' } } -KnownApiVersions @('2026-03-18','2025-09-01','2025-05-01','2025-05-01-preview','2024-09-01-preview','2023-06-01-preview','2023-04-01','2023-04-01-preview','2023-03-31','2023-03-01-preview','2022-07-01-preview','2021-10-01-preview')
        New-ArmOperationPreset -Name 'AcsEmailDomainUpdate' -Category 'ACS.Email' -Description 'Patch an ACS email domain.' -Method 'PATCH' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Communication/emailServices/{emailServiceName}/domains/{domainName}' -DefaultApiVersion '2023-03-31' -Aliases @('update-email-domain','patch-email-domain') -ProviderNamespace 'Microsoft.Communication' -ResourceType 'emailServices/domains' -RequiredParameters @('subscriptionId','resourceGroupName','emailServiceName','domainName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example'; emailServiceName='mailsvc1'; domainName='contoso.com' } -ExampleBody @{ properties=@{ userEngagementTracking='Enabled' } } -KnownApiVersions @('2026-03-18','2025-09-01','2025-05-01','2025-05-01-preview','2024-09-01-preview','2023-06-01-preview','2023-04-01','2023-04-01-preview','2023-03-31','2023-03-01-preview','2022-07-01-preview','2021-10-01-preview')
        New-ArmOperationPreset -Name 'AcsEmailDomainDelete' -Category 'ACS.Email' -Description 'Delete an ACS email domain.' -Method 'DELETE' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Communication/emailServices/{emailServiceName}/domains/{domainName}' -DefaultApiVersion '2023-03-31' -Aliases @('remove-email-domain','delete-email-domain') -ProviderNamespace 'Microsoft.Communication' -ResourceType 'emailServices/domains' -RequiredParameters @('subscriptionId','resourceGroupName','emailServiceName','domainName') -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example'; emailServiceName='mailsvc1'; domainName='contoso.com' } -KnownApiVersions @('2026-03-18','2025-09-01','2025-05-01','2025-05-01-preview','2024-09-01-preview','2023-06-01-preview','2023-04-01','2023-04-01-preview','2023-03-31','2023-03-01-preview','2022-07-01-preview','2021-10-01-preview')
        New-ArmOperationPreset -Name 'AcsEmailDomainInitiateVerification' -Category 'ACS.Email' -Description 'Initiate Domain, SPF, DKIM, DKIM2, or DMARC verification for an ACS email domain.' -Method 'POST' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Communication/emailServices/{emailServiceName}/domains/{domainName}/initiateVerification' -DefaultApiVersion '2023-03-31' -Aliases @('acs-domain-initiate-verification','verify-email-domain','dkim-verify') -ProviderNamespace 'Microsoft.Communication' -ResourceType 'emailServices/domains' -RequiredParameters @('subscriptionId','resourceGroupName','emailServiceName','domainName','verificationType') -OptionalParameters @('subscriptionId') -DefaultBodyTemplate @{ verificationType='{verificationType}' } -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example'; emailServiceName='mailsvc1'; domainName='contoso.com'; verificationType='DKIM2' } -ExampleBody @{ verificationType='DKIM2' } -KnownApiVersions @('2026-03-18','2025-09-01','2025-05-01','2025-05-01-preview','2024-09-01-preview','2023-06-01-preview','2023-04-01','2023-04-01-preview','2023-03-31','2023-03-01-preview','2022-07-01-preview','2021-10-01-preview') -Notes @('Accepted verification types include Domain, SPF, DKIM, DKIM2, and DMARC.','If -Body is not provided, the preset auto-builds {"verificationType":"<value>"} from -OperationParameters.')
        New-ArmOperationPreset -Name 'AcsEmailDomainCancelVerification' -Category 'ACS.Email' -Description 'Cancel Domain, SPF, DKIM, DKIM2, or DMARC verification for an ACS email domain.' -Method 'POST' -RelativePathTemplate '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Communication/emailServices/{emailServiceName}/domains/{domainName}/cancelVerification' -DefaultApiVersion '2023-03-31' -Aliases @('acs-domain-cancel-verification','stop-email-domain-verification') -ProviderNamespace 'Microsoft.Communication' -ResourceType 'emailServices/domains' -RequiredParameters @('subscriptionId','resourceGroupName','emailServiceName','domainName','verificationType') -DefaultBodyTemplate @{ verificationType='{verificationType}' } -ExampleParameters @{ subscriptionId='<subscription-id>'; resourceGroupName='rg-example'; emailServiceName='mailsvc1'; domainName='contoso.com'; verificationType='DKIM2' } -ExampleBody @{ verificationType='DKIM2' } -KnownApiVersions @('2026-03-18','2025-09-01','2025-05-01','2025-05-01-preview','2024-09-01-preview','2023-06-01-preview','2023-04-01','2023-04-01-preview','2023-03-31','2023-03-01-preview','2022-07-01-preview','2021-10-01-preview') -Notes @('Accepted verification types include Domain, SPF, DKIM, DKIM2, and DMARC.','If -Body is not provided, the preset auto-builds {"verificationType":"<value>"} from -OperationParameters.')
    )
}

function Get-ArmOperationPreset {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Name)
    $match = Get-ArmOperationPresetCatalog | Where-Object { $_.Name -eq $Name -or $_.Aliases -contains $Name } | Select-Object -First 1
    if ($null -eq $match) { throw "Operation '$Name' was not found. Use -ListOperations to view the available preset names and aliases." }
    $match
}

function ConvertTo-OperationParameterLookup {
    [CmdletBinding()] param([AllowNull()][Collections.IDictionary]$InputParameters)
    $lookup = @{}
    if ($null -ne $InputParameters) { foreach ($key in $InputParameters.Keys) { $lookup[[string]$key] = $InputParameters[$key] } }
    if (-not $lookup.ContainsKey('subscriptionId')) {
        if ($SubscriptionId) { $lookup['subscriptionId'] = $SubscriptionId }
        else {
            $context = Get-CurrentAzContextSafe
            if ($context -and $context.SubscriptionId) { $lookup['subscriptionId'] = $context.SubscriptionId }
        }
    }
    $lookup
}

function Get-OperationParameterValueRequired {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][hashtable]$Parameters,[Parameter(Mandatory=$true)][string]$Name)
    $value = Get-HashtableValueIgnoreCase -Table $Parameters -Key $Name
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) { throw "Operation parameter '$Name' is required. Supply it through -OperationParameters @{ $Name = 'value' }." }
    [string]$value
}

function Resolve-OperationPathTemplate {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Template,[Parameter(Mandatory=$true)][hashtable]$Parameters)
    $resolved = [regex]::Replace($Template,'\{([A-Za-z0-9]+)\}',{ param($m) [Uri]::EscapeDataString((Get-OperationParameterValueRequired -Parameters $Parameters -Name $m.Groups[1].Value)) })
    if ($resolved.StartsWith('/')) { return $resolved }
    '/' + $resolved
}

function Resolve-OperationObjectTemplate {
    [CmdletBinding()] param([AllowNull()][object]$Template,[Parameter(Mandatory=$true)][hashtable]$Parameters)
    if ($null -eq $Template) { return $null }
    if ($Template -is [string]) {
        if ($Template -match '^\{([A-Za-z0-9]+)\}$') { return (Get-OperationParameterValueRequired -Parameters $Parameters -Name $Matches[1]) }
        return ([regex]::Replace($Template,'\{([A-Za-z0-9]+)\}',{ param($m) (Get-OperationParameterValueRequired -Parameters $Parameters -Name $m.Groups[1].Value) }))
    }
    if ($Template -is [Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in $Template.Keys) { $result[[string]$key] = Resolve-OperationObjectTemplate -Template $Template[$key] -Parameters $Parameters }
        return $result
    }
    if ($Template -is [Collections.IEnumerable] -and $Template -isnot [string]) {
        $items = [Collections.Generic.List[object]]::new()
        foreach ($item in $Template) { $items.Add((Resolve-OperationObjectTemplate -Template $item -Parameters $Parameters)) }
        return $items.ToArray()
    }
    $Template
}

function ConvertTo-ApiVersionSortInfo {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$ApiVersionValue)
    $dateValue = [datetime]::MinValue; $suffix = ''
    if ($ApiVersionValue -match '^(?<date>\d{4}-\d{2}-\d{2})(?<suffix>.*)$') { $dateValue = [datetime]::ParseExact($Matches['date'],'yyyy-MM-dd',$null); $suffix = $Matches['suffix'] }
    [pscustomobject]@{ ApiVersion=$ApiVersionValue; Date=$dateValue; IsPreview=($ApiVersionValue -like '*preview*'); Suffix=$suffix }
}

function Sort-ApiVersionList {
    [CmdletBinding()] param([string[]]$ApiVersionsToSort)
    @($ApiVersionsToSort | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique | ForEach-Object { ConvertTo-ApiVersionSortInfo -ApiVersionValue $_ } | Sort-Object @{ Expression='Date'; Descending=$true }, @{ Expression='IsPreview'; Descending=$false }, @{ Expression='ApiVersion'; Descending=$true } | ForEach-Object { $_.ApiVersion })
}

function Get-LatestStableApiVersion { [CmdletBinding()] param([string[]]$ApiVersionsToInspect) $stable = @($ApiVersionsToInspect | Where-Object { $_ -notlike '*preview*' }); if($stable.Count -gt 0){ return $stable[0] }; if($ApiVersionsToInspect.Count -gt 0){ return $ApiVersionsToInspect[0] }; $null }

function Get-ProviderMetadataSafe {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$ProviderNamespace)
    $cacheKey = $ProviderNamespace.ToLowerInvariant()
    if ($script:SessionState.ProviderMetadataCache.ContainsKey($cacheKey)) { return $script:SessionState.ProviderMetadataCache[$cacheKey] }
    $path = '/providers/{0}?api-version={1}' -f $ProviderNamespace,$script:Configuration.ProviderMetadataApiVersion
    $response = Invoke-AzRestMethod -Method 'GET' -Path $path -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($response.Content)) { throw "Provider metadata for '$ProviderNamespace' was empty." }
    $metadata = $response.Content | ConvertFrom-Json -ErrorAction Stop
    $script:SessionState.ProviderMetadataCache[$cacheKey] = $metadata
    $metadata
}

function Find-ProviderResourceTypeMetadata {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][object]$ProviderMetadata,[Parameter(Mandatory=$true)][string]$ResourceType)
    @($ProviderMetadata.resourceTypes | Where-Object { [string]::Equals([string]$_.resourceType,$ResourceType,[StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1)
}

function Get-ArmOperationApiVersionInfo {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][pscustomobject]$Preset)
    $apiVersions = @(); $source = 'Preset'; $discoveryError = $null
    if ($Preset.ProviderNamespace -and $Preset.ResourceType) {
        try {
            $providerMetadata = Get-ProviderMetadataSafe -ProviderNamespace $Preset.ProviderNamespace
            $resourceTypeMetadata = Find-ProviderResourceTypeMetadata -ProviderMetadata $providerMetadata -ResourceType $Preset.ResourceType
            if ($resourceTypeMetadata -and $resourceTypeMetadata.apiVersions) { $apiVersions = @($resourceTypeMetadata.apiVersions); $source = 'ProviderMetadata' }
        }
        catch { $discoveryError = $_.Exception.Message }
    }
    if ($apiVersions.Count -lt 1) { $apiVersions = @($Preset.KnownApiVersions); if($apiVersions.Count -lt 1 -and $Preset.DefaultApiVersion){ $apiVersions = @($Preset.DefaultApiVersion) } }
    $sorted = Sort-ApiVersionList -ApiVersionsToSort $apiVersions
    [pscustomobject]@{ Name=$Preset.Name; Category=$Preset.Category; ProviderNamespace=$Preset.ProviderNamespace; ResourceType=$Preset.ResourceType; DefaultApiVersion=$Preset.DefaultApiVersion; LatestStableApiVersion=(Get-LatestStableApiVersion -ApiVersionsToInspect $sorted); ApiVersions=$sorted; Source=$source; DiscoveryError=$discoveryError }
}

function Resolve-ArmOperationRequest {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Name,[AllowNull()][Collections.IDictionary]$Parameters)
    $preset = Get-ArmOperationPreset -Name $Name
    $lookup = ConvertTo-OperationParameterLookup -InputParameters $Parameters
    foreach ($requiredParameter in @($preset.RequiredParameters)) { $null = Get-OperationParameterValueRequired -Parameters $lookup -Name $requiredParameter }
    $effectiveBody = $null
    $scriptBoundParameters = @($script:SessionState.BoundParameterNames)
    if (-not ($scriptBoundParameters -contains 'Body') -and -not ($scriptBoundParameters -contains 'BodyFile') -and $null -ne $preset.DefaultBodyTemplate) { $effectiveBody = Resolve-OperationObjectTemplate -Template $preset.DefaultBodyTemplate -Parameters $lookup | ConvertTo-Json -Depth $script:Configuration.DefaultJsonDepth -Compress }
    [pscustomobject]@{ Preset=$preset; Method=if($scriptBoundParameters -contains 'Method'){$Method}else{$preset.Method}; RelativePath=(Resolve-OperationPathTemplate -Template $preset.RelativePathTemplate -Parameters $lookup); ApiVersion=if($scriptBoundParameters -contains 'ApiVersion'){$ApiVersion}else{$preset.DefaultApiVersion}; Body=$effectiveBody; Parameters=$lookup }
}

function Show-ArmOperationPresetCatalog {
    [CmdletBinding()] param()
    $catalog = Get-ArmOperationPresetCatalog | Sort-Object Category,Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; Aliases=$_.Aliases; Category=$_.Category; Method=$_.Method; DefaultApiVersion=$_.DefaultApiVersion; Description=$_.Description } }
    Write-Output ($catalog | ConvertTo-Json -Depth 10)
}

function Show-ArmOperationPresetDetails {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Name,[switch]$IncludeApiVersions)
    $preset = Get-ArmOperationPreset -Name $Name
    $detail = [ordered]@{ Name=$preset.Name; Aliases=$preset.Aliases; Category=$preset.Category; Description=$preset.Description; Method=$preset.Method; RelativePathTemplate=$preset.RelativePathTemplate; DefaultApiVersion=$preset.DefaultApiVersion; ProviderNamespace=$preset.ProviderNamespace; ResourceType=$preset.ResourceType; RequiredParameters=$preset.RequiredParameters; OptionalParameters=$preset.OptionalParameters; ExampleParameters=$preset.ExampleParameters; ExampleBody=$preset.ExampleBody; Notes=$preset.Notes }
    if ($IncludeApiVersions) { $detail['ApiVersionInfo'] = Get-ArmOperationApiVersionInfo -Preset $preset }
    Write-Output ($detail | ConvertTo-Json -Depth 20)
}

function Show-ArmOperationApiVersions {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Name)
    $preset = Get-ArmOperationPreset -Name $Name
    Write-Output ((Get-ArmOperationApiVersionInfo -Preset $preset) | ConvertTo-Json -Depth 10)
}

# ARM request helpers. These functions normalize URIs, validate headers/body
# content, invoke the request, and unwrap ARM-specific response patterns.
function ConvertFrom-QueryStringSafe { [CmdletBinding()] param([string]$Query) $table=[ordered]@{}; if([string]::IsNullOrWhiteSpace($Query)){return $table}; foreach($pair in ($Query.TrimStart('?') -split '&')){ if([string]::IsNullOrWhiteSpace($pair)){continue}; $name,$value=$pair -split '=',2; $table[[Net.WebUtility]::UrlDecode($name)] = if($null -ne $value){ [Net.WebUtility]::UrlDecode($value) } else { '' } }; $table }
function ConvertTo-QueryStringSafe { [CmdletBinding()] param([Parameter(Mandatory=$true)][hashtable]$Table) (($Table.Keys | % { '{0}={1}' -f [Net.WebUtility]::UrlEncode([string]$_), [Net.WebUtility]::UrlEncode([string]$Table[$_]) }) -join '&') }

function Resolve-ArmUri {
    [CmdletBinding()] param([System.Uri]$RequestUri,[string]$RequestRelativePath,[string]$RequestApiVersion)
    if (-not $RequestUri -and [string]::IsNullOrWhiteSpace($RequestRelativePath)) { throw 'Either -Uri, -RelativePath, or -Operation must be supplied for an ARM request. Use -RelativePath for ARM paths such as /subscriptions/<id>/resourceGroups/<name>.' }
    $context = Get-CurrentAzContextSafe; if ($null -eq $context) { throw 'A valid Azure context is required before resolving an ARM URI.' }
    $environmentObject = Get-AzEnvironmentSafe -Name $context.Environment
    if ($null -eq $environmentObject -or [string]::IsNullOrWhiteSpace($environmentObject.ResourceManagerUrl)) { throw "Unable to determine the Resource Manager endpoint for environment '$($context.Environment)'." }
    $resourceManagerUrl = $environmentObject.ResourceManagerUrl.TrimEnd('/')
    if ($RequestUri) {
        # Absolute URIs are supported, but ARM requests still have to remain
        # HTTPS-only and include api-version when they target the ARM endpoint.
        if (-not $RequestUri.IsAbsoluteUri) { throw 'The supplied -Uri value must be an absolute HTTPS URI.' }
        if ($RequestUri.Scheme -ne 'https') { throw 'Only HTTPS ARM URIs are supported.' }
        $builder = [System.UriBuilder]::new($RequestUri); $queryTable = ConvertFrom-QueryStringSafe -Query $builder.Query; $resourceManagerHost = ([System.Uri]$resourceManagerUrl).Host
        if ($builder.Host -eq $resourceManagerHost) { if ($RequestApiVersion) { $queryTable['api-version'] = $RequestApiVersion } elseif (-not $queryTable.Contains('api-version')) { throw 'An ARM request against the Resource Manager endpoint must include api-version either in the URI or through -ApiVersion.' } }
        $builder.Query = ConvertTo-QueryStringSafe -Table $queryTable
        return [pscustomobject]@{ Mode='Uri'; Uri=$builder.Uri; Path=$builder.Uri.PathAndQuery; ResourceManagerUrl=$resourceManagerUrl }
    }
    $normalizedPath = if ($RequestRelativePath.StartsWith('/')) { $RequestRelativePath } else { '/' + $RequestRelativePath }
    $builder = [System.UriBuilder]::new($resourceManagerUrl + $normalizedPath); $queryTable = ConvertFrom-QueryStringSafe -Query $builder.Query
    if ($RequestApiVersion) { $queryTable['api-version'] = $RequestApiVersion } elseif (-not $queryTable.Contains('api-version')) { throw 'A relative ARM path must include api-version either in the path query string or through -ApiVersion. Example: -ApiVersion 2021-04-01' }
    $builder.Query = ConvertTo-QueryStringSafe -Table $queryTable
    [pscustomobject]@{ Mode='Path'; Uri=$builder.Uri; Path=$builder.Uri.PathAndQuery; ResourceManagerUrl=$resourceManagerUrl }
}
function Test-JsonContent { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Content,[string]$ContentSource='request body') if([string]::IsNullOrWhiteSpace($Content)){ throw "The $ContentSource is empty." }; try { ($Content | ConvertFrom-Json -ErrorAction Stop | ConvertTo-Json -Depth $script:Configuration.DefaultJsonDepth -Compress) } catch { throw "The $ContentSource is not valid JSON. $($_.Exception.Message)" } }
function Get-ValidatedHeaders { [CmdletBinding()] param([hashtable]$InputHeaders) $validated=@{}; if($null -eq $InputHeaders){return $validated}; foreach($entry in $InputHeaders.GetEnumerator()){ $name=[string]$entry.Key; $value=[string]$entry.Value; if([string]::IsNullOrWhiteSpace($name)){throw 'Custom header names cannot be empty.'}; if($name -notmatch '^[A-Za-z0-9-]+$'){throw "Custom header '$name' contains invalid characters."}; if($script:Configuration.DangerousHeaders -contains $name){throw "Custom header '$name' is blocked for security reasons."}; if($value -match '[\r\n]'){throw "Custom header '$name' contains a newline, which is not allowed."}; $validated[$name]=$value }; $validated }
function ConvertTo-PlainTextFromSecureString { [CmdletBinding()] param([Parameter(Mandatory=$true)][Security.SecureString]$SecureString) $pointer=[IntPtr]::Zero; try { $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString); [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) } finally { if($pointer -ne [IntPtr]::Zero){ [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) } } }
function Get-AuthorizationHeaderFromAzContext { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$ResourceUrl) $tokenResult=Get-AzAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop; if($null -eq $tokenResult){ throw 'Get-AzAccessToken did not return an access token.' }; $token = if($tokenResult.Token -is [Security.SecureString]){ ConvertTo-PlainTextFromSecureString -SecureString $tokenResult.Token } else { [string]$tokenResult.Token }; if([string]::IsNullOrWhiteSpace($token)){ throw 'Get-AzAccessToken returned an empty access token.' }; @{ Authorization = ('Bearer ' + $token) } }

function ConvertTo-HeaderHashtable { [CmdletBinding()] param([AllowNull()][object]$HeaderObject) $table=@{}; if($null -eq $HeaderObject){return $table}; if($HeaderObject -is [Collections.IDictionary]){ foreach($key in $HeaderObject.Keys){ $value=$HeaderObject[$key]; $table[[string]$key] = if($value -is [Array]){ [string]($value -join ',') } else { [string]$value } } } else { foreach($property in $HeaderObject.PSObject.Properties){ $table[$property.Name] = [string]$property.Value } }; $table }
function Get-HeaderValue { [CmdletBinding()] param([Parameter(Mandatory=$true)][hashtable]$Headers,[Parameter(Mandatory=$true)][string]$Name) foreach($key in $Headers.Keys){ if([string]::Equals([string]$key,$Name,[StringComparison]::OrdinalIgnoreCase)){ return [string]$Headers[$key] } }; $null }
function Get-ArmResponseIdentifiers { [CmdletBinding()] param([Parameter(Mandatory=$true)][hashtable]$Headers) $correlationId=$null; foreach($name in $script:Configuration.CorrelationHeaderNames){ $correlationId=Get-HeaderValue -Headers $Headers -Name $name; if($correlationId){break} }; $requestId=$null; foreach($name in $script:Configuration.RequestHeaderNames){ $requestId=Get-HeaderValue -Headers $Headers -Name $name; if($requestId){break} }; [pscustomobject]@{ CorrelationId=$correlationId; RequestId=$requestId } }
function ConvertTo-ArmResponseObject { [CmdletBinding()] param([Parameter(Mandatory=$true)][object]$Response,[Parameter(Mandatory=$true)][string]$MethodName,[Parameter(Mandatory=$true)][System.Uri]$RequestUri) $headers=ConvertTo-HeaderHashtable -HeaderObject $Response.Headers; $ids=Get-ArmResponseIdentifiers -Headers $headers; [pscustomobject]@{ StatusCode=[int]$Response.StatusCode; Headers=$headers; Content=[string]$Response.Content; Method=$MethodName; RequestUri=[string]$RequestUri; CorrelationId=$ids.CorrelationId; RequestId=$ids.RequestId; IsSuccessStatus=(([int]$Response.StatusCode -ge 200) -and ([int]$Response.StatusCode -lt 300)) } }

function Read-HttpErrorResponse {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][Exception]$Exception,[Parameter(Mandatory=$true)][string]$MethodName,[Parameter(Mandatory=$true)][System.Uri]$RequestUri)
    $webResponse = if($Exception.PSObject.Properties['Response']) { $Exception.Response } else { $null }
    if ($null -eq $webResponse) { throw $Exception }
    $content=''; try { $stream=$webResponse.GetResponseStream(); if($stream){ $reader=[IO.StreamReader]::new($stream); try { $content=$reader.ReadToEnd() } finally { $reader.Dispose(); $stream.Dispose() } } } catch { $content=$Exception.Message }
    $response=[pscustomobject]@{ StatusCode=[int]$webResponse.StatusCode; Headers=ConvertTo-HeaderHashtable -HeaderObject $webResponse.Headers; Content=$content }
    ConvertTo-ArmResponseObject -Response $response -MethodName $MethodName -RequestUri $RequestUri
}

function Get-ArmErrorDetails {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][pscustomobject]$Response)
    $parsed=$null; try { if(-not [string]::IsNullOrWhiteSpace($Response.Content)){ $parsed=$Response.Content | ConvertFrom-Json -ErrorAction Stop } } catch { $parsed=$null }
    $errorObject = if($parsed -and $parsed.error){ $parsed.error } else { $parsed }
    [pscustomobject]@{ Code=if($errorObject -and $errorObject.code){[string]$errorObject.code}else{$null}; Message=if($errorObject -and $errorObject.message){[string]$errorObject.message}else{Redact-SensitiveText -Text $Response.Content}; Target=if($errorObject -and $errorObject.target){[string]$errorObject.target}else{$null}; Details=if($errorObject -and $errorObject.details){$errorObject.details}else{$null}; CorrelationId=$Response.CorrelationId; RequestId=$Response.RequestId }
}

function Invoke-ArmRequestCore {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$RequestMethod,[Parameter(Mandatory=$true)][pscustomobject]$RequestInfo,[AllowNull()][string]$Payload,[Parameter(Mandatory=$true)][hashtable]$ValidatedHeaders)
    Write-Log -Level 'INFO' -Message ("Invoking ARM request: {0} {1}" -f $RequestMethod,$RequestInfo.Uri.AbsoluteUri)
    if($ValidatedHeaders.Count -gt 0){ Write-Log -Level 'DEBUG' -Message 'Custom ARM headers were supplied.' -Data $ValidatedHeaders }
    if($Payload){ Write-Log -Level 'DEBUG' -Message 'ARM request payload prepared.' -Data $Payload }
    $response=$null; $manualHeaders=($ValidatedHeaders.Count -gt 0)
    if(-not $manualHeaders){
        # Use the Az cmdlet path whenever no extra caller headers are needed.
        try {
            $params=@{ Method=$RequestMethod; ErrorAction='Stop' }
            if($Payload){ $params['Payload']=$Payload }
            if($RequestInfo.Mode -eq 'Path'){ $params['Path']=$RequestInfo.Path } else { $params['Uri']=$RequestInfo.Uri }
            $azResponse=Invoke-AzRestMethod @params
            $response=ConvertTo-ArmResponseObject -Response $azResponse -MethodName $RequestMethod -RequestUri $RequestInfo.Uri
        } catch {
            if($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response){ $response=Read-HttpErrorResponse -Exception $_.Exception -MethodName $RequestMethod -RequestUri $RequestInfo.Uri } else { throw }
        }
    } else {
        # Fall back to Invoke-WebRequest when custom headers are required so the
        # script can merge caller headers with an Az-issued bearer token.
        $authHeader=Get-AuthorizationHeaderFromAzContext -ResourceUrl $RequestInfo.ResourceManagerUrl; $webHeaders=@{}; foreach($entry in $authHeader.GetEnumerator()){ $webHeaders[$entry.Key]=$entry.Value }; foreach($entry in $ValidatedHeaders.GetEnumerator()){ $webHeaders[$entry.Key]=$entry.Value }
        try {
            $params=@{ Uri=$RequestInfo.Uri.AbsoluteUri; Method=$RequestMethod; Headers=$webHeaders; ErrorAction='Stop' }
            if($Payload){ $params['Body']=$Payload; $params['ContentType']='application/json' }
            if($PSVersionTable.PSVersion.Major -lt 6){ $params['UseBasicParsing']=$true }
            $webResponse=Invoke-WebRequest @params
            $temp=[pscustomobject]@{ StatusCode=[int]$webResponse.StatusCode; Headers=ConvertTo-HeaderHashtable -HeaderObject $webResponse.Headers; Content=[string]$webResponse.Content }
            $response=ConvertTo-ArmResponseObject -Response $temp -MethodName $RequestMethod -RequestUri $RequestInfo.Uri
        } catch { $response=Read-HttpErrorResponse -Exception $_.Exception -MethodName $RequestMethod -RequestUri $RequestInfo.Uri } finally { if($webHeaders.ContainsKey('Authorization')){ $webHeaders['Authorization']='[REDACTED]' } }
    }
    if($response.CorrelationId -or $response.RequestId){ Write-Log -Level 'INFO' -Message ('ARM response received. StatusCode={0}; CorrelationId={1}; RequestId={2}' -f $response.StatusCode,$response.CorrelationId,$response.RequestId) } else { Write-Log -Level 'INFO' -Message ('ARM response received. StatusCode={0}' -f $response.StatusCode) }
    if(-not $response.IsSuccessStatus){ $errorDetails=Get-ArmErrorDetails -Response $response; $summary = if($errorDetails.Code){ '{0}: {1}' -f $errorDetails.Code,$errorDetails.Message } else { $response.Content }; throw "ARM request failed. StatusCode=$($response.StatusCode). $summary" }
    $response
}

function Get-LongRunningOperationState { [CmdletBinding()] param([Parameter(Mandatory=$true)][pscustomobject]$Response) $status=$null; try { if(-not [string]::IsNullOrWhiteSpace($Response.Content)){ $contentObject=$Response.Content | ConvertFrom-Json -ErrorAction Stop; if($contentObject.status){$status=[string]$contentObject.status}elseif($contentObject.properties -and $contentObject.properties.provisioningState){$status=[string]$contentObject.properties.provisioningState} } } catch { $status=$null }; if($status){return $status}; if($Response.StatusCode -in 200,201,204){'Succeeded'} else {'InProgress'} }

function Wait-ArmLongRunningOperation {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][pscustomobject]$InitialResponse,[Parameter(Mandatory=$true)][pscustomobject]$InitialRequestInfo,[Parameter(Mandatory=$true)][string]$InitialMethod,[Parameter(Mandatory=$true)][hashtable]$ValidatedHeaders)
    # ARM long-running operations advertise their polling endpoints in response
    # headers. If neither header exists, the first response is already final.
    $asyncUri = Get-HeaderValue -Headers $InitialResponse.Headers -Name 'Azure-AsyncOperation'; if(-not $asyncUri){ $asyncUri = Get-HeaderValue -Headers $InitialResponse.Headers -Name 'Operation-Location' }
    $locationUri = Get-HeaderValue -Headers $InitialResponse.Headers -Name 'Location'; if(-not $asyncUri -and -not $locationUri){ return $InitialResponse }
    $pollUri = if($asyncUri){$asyncUri}else{$locationUri}; $deadline=(Get-Date).AddSeconds($script:Configuration.LongRunningTimeoutSeconds); $latestResponse=$InitialResponse
    while((Get-Date) -lt $deadline){
        # Honor Retry-After when present so polling remains service-friendly.
        $retryAfterValue = Get-HeaderValue -Headers $latestResponse.Headers -Name 'Retry-After'; $delaySeconds = if($retryAfterValue -and ($retryAfterValue -as [int])){ [int]$retryAfterValue } else { $script:Configuration.DefaultPollIntervalSeconds }; if($delaySeconds -lt 1){$delaySeconds=$script:Configuration.DefaultPollIntervalSeconds}
        Write-Log -Level 'INFO' -Message ("Polling long-running ARM operation in {0} second(s)." -f $delaySeconds); Start-Sleep -Seconds $delaySeconds
        $pollRequestInfo=[pscustomobject]@{ Mode='Uri'; Uri=[System.Uri]$pollUri; Path=([System.Uri]$pollUri).PathAndQuery; ResourceManagerUrl=$InitialRequestInfo.ResourceManagerUrl }
        $latestResponse=Get-LastPipelineValueSafe -Values @(Invoke-ArmRequestCore -RequestMethod 'GET' -RequestInfo $pollRequestInfo -Payload $null -ValidatedHeaders $ValidatedHeaders)
        $state=Get-LongRunningOperationState -Response $latestResponse; Write-Log -Level 'INFO' -Message ("Long-running ARM operation state: {0}" -f $state)
        switch -Regex ($state) {
            '^(Succeeded)$' { if($InitialMethod -ne 'DELETE'){ return (Get-LastPipelineValueSafe -Values @(Invoke-ArmRequestCore -RequestMethod 'GET' -RequestInfo $InitialRequestInfo -Payload $null -ValidatedHeaders $ValidatedHeaders)) }; return $latestResponse }
            '^(Failed|Canceled|Cancelled)$' { $errorDetails=Get-ArmErrorDetails -Response $latestResponse; throw "Long-running ARM operation failed. $($errorDetails.Code): $($errorDetails.Message)" }
            default { continue }
        }
    }
    throw "Long-running ARM operation did not complete within $($script:Configuration.LongRunningTimeoutSeconds) seconds."
}
function Format-ArmResponse { [CmdletBinding()] param([Parameter(Mandatory=$true)][pscustomobject]$Response) if($RawOutput){ return [string]$Response.Content }; if([string]::IsNullOrWhiteSpace($Response.Content)){ return '' }; try { ($Response.Content | ConvertFrom-Json -ErrorAction Stop | ConvertTo-Json -Depth $script:Configuration.DefaultJsonDepth) } catch { [string]$Response.Content } }
function Save-ArmResponse { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$FormattedContent) if(-not $OutputFile){ return }; $resolved=if([IO.Path]::IsPathRooted($OutputFile)){$OutputFile}else{ Join-Path $script:SessionState.OutputPath $OutputFile }; Ensure-Directory -Path (Split-Path $resolved -Parent); Set-Content -LiteralPath $resolved -Value $FormattedContent -Encoding UTF8; Write-Log -Level 'INFO' -Message "Saved ARM response content to '$resolved'." }
function Clear-ArmClientPsContext { [CmdletBinding()] param() try { Clear-AzContext -Scope Process -Force -ErrorAction Stop | Out-Null } catch { Write-Log -Level 'DEBUG' -Message 'Clear-AzContext did not complete cleanly.' -Data $_.Exception.Message }; try { Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue | Out-Null } catch { Write-Log -Level 'DEBUG' -Message 'Disconnect-AzAccount did not complete cleanly.' -Data $_.Exception.Message }; Write-Log -Level 'INFO' -Message 'Cleared Azure context from the current process.' }

function Show-BundledModuleVersionSummary {
    [CmdletBinding()] param()
    $manifest = Get-VersionsManifestSafe
    if ($manifest -and $manifest.modules) { Write-Output ($manifest.modules | Sort-Object name,version | ConvertTo-Json -Depth 10); return }
    $inventory = @(Get-ChildItem -LiteralPath $script:SessionState.ModulesPath -Recurse -Filter '*.psd1' -File | ForEach-Object { $data=Import-ModuleManifestDataSafe -ManifestPath $_.FullName; if($data){ $rootModule=Get-ManifestValueSafe -ManifestData $data -Name 'RootModule'; $moduleVersion=Get-ManifestValueSafe -ManifestData $data -Name 'ModuleVersion'; [pscustomobject]@{ Name=if($rootModule){ [IO.Path]::GetFileNameWithoutExtension([string]$rootModule) } else { [IO.Path]::GetFileNameWithoutExtension($_.Name) }; Version=[string]$moduleVersion; Manifest=$_.FullName; ModuleBase=$_.Directory.FullName } } })
    Write-Output ($inventory | Sort-Object Name,Version | ConvertTo-Json -Depth 10)
}

function Show-ResolvedModuleVersionSummary {
    [CmdletBinding()] param()
    if ($script:SessionState.ResolvedModules.Count -lt 1) { $script:SessionState.ResolvedModules = @(Get-ResolvedModuleTable) }
    $summary = foreach ($resolution in $script:SessionState.ResolvedModules) { $candidate = if($resolution.SelectedCandidate){$resolution.SelectedCandidate}else{$resolution.PreferredCandidate}; [pscustomobject]@{ Name=$resolution.Name; SelectedFrom=$candidate.Source; Version=$candidate.Version; ManifestPath=$candidate.ManifestPath; ModuleBase=$candidate.ModuleBase; SelectionMode=$resolution.SelectionMode } }
    Write-Output ($summary | Sort-Object Name | ConvertTo-Json -Depth 10)
}

function Invoke-ArmClientSelfTest {
    [CmdletBinding()] param()
    # Self-test verifies local package health without requiring a live ARM call.
    $results = [Collections.Generic.List[object]]::new()
    foreach ($path in @($script:SessionState.ScriptRoot,$script:SessionState.ModulesPath,$script:SessionState.ManifestPath,$script:SessionState.LogsPath,$script:SessionState.OutputPath)) { $results.Add([pscustomobject]@{ Test='PathExists'; Target=$path; Result=(Test-Path -LiteralPath $path) }) }
    if (-not $SkipHashValidation) { Test-BundledModuleFiles; $results.Add([pscustomobject]@{ Test='HashValidation'; Target=(Join-Path $script:SessionState.ManifestPath $script:Configuration.FileHashManifestName); Result=$true }) } else { $results.Add([pscustomobject]@{ Test='HashValidation'; Target='Skipped'; Result=$false }) }
    $resolved = if($script:SessionState.ResolvedModules.Count -gt 0){$script:SessionState.ResolvedModules}else{Get-ResolvedModuleTable}
    foreach($module in $resolved){ $candidate=if($module.SelectedCandidate){$module.SelectedCandidate}else{$module.PreferredCandidate}; $results.Add([pscustomobject]@{ Test='ModuleResolution'; Target=$module.Name; Result=($null -ne $candidate); Source=$candidate.Source; Path=$candidate.ManifestPath; Version=$candidate.Version }) }
    $context = Get-CurrentAzContextSafe; $results.Add([pscustomobject]@{ Test='CurrentAzContextAvailable'; Target='AzureContext'; Result=($null -ne $context) })
    Write-Output ($results | ConvertTo-Json -Depth 10)
}

function Initialize-Environment {
    [CmdletBinding()] param()
    # Resolve and create runtime folders once so later code can use the shared
    # session state instead of rebuilding paths repeatedly.
    $script:SessionState.ScriptRoot = Get-ScriptRoot
    $script:SessionState.ModulesPath = Join-Path $script:SessionState.ScriptRoot $script:Configuration.ModulesDirectoryName
    $script:SessionState.ManifestPath = Join-Path $script:SessionState.ScriptRoot $script:Configuration.ManifestDirectoryName
    $script:SessionState.LogsPath = Join-Path $script:SessionState.ScriptRoot $script:Configuration.DefaultLogDirectoryName
    $script:SessionState.OutputPath = Join-Path $script:SessionState.ScriptRoot $script:Configuration.DefaultOutputDirectoryName
    Ensure-Directory -Path $script:SessionState.LogsPath; Ensure-Directory -Path $script:SessionState.OutputPath
    $script:SessionState.LogFilePath = if($LogPath){ if([IO.Path]::IsPathRooted($LogPath)){$LogPath}else{ Join-Path $script:SessionState.LogsPath $LogPath } } else { Join-Path $script:SessionState.LogsPath ('ArmClient-PS_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss')) }
    Ensure-Directory -Path (Split-Path $script:SessionState.LogFilePath -Parent)
    Write-Log -Level 'INFO' -Message ('Starting {0} version {1}.' -f $script:Configuration.ToolName,$script:Configuration.Version)
    foreach($required in @($script:SessionState.ModulesPath,$script:SessionState.ManifestPath)){ if(-not (Test-Path -LiteralPath $required -PathType Container)){ throw "Required path '$required' does not exist." } }
}

function Invoke-ArmRequest {
    [CmdletBinding()] param()
    $operationRequest = $null
    if ($Operation) { $operationRequest = Resolve-ArmOperationRequest -Name $Operation -Parameters $OperationParameters }
    $requestMethod = if($operationRequest){$operationRequest.Method}else{$Method}
    $requestUri = if($operationRequest){$null}else{$Uri}
    $requestRelativePath = if($operationRequest){$operationRequest.RelativePath}else{$RelativePath}
    $requestApiVersion = if($operationRequest){$operationRequest.ApiVersion}else{$ApiVersion}
    $validatedHeaders = Get-ValidatedHeaders -InputHeaders $Headers
    $requestInfo = Resolve-ArmUri -RequestUri $requestUri -RequestRelativePath $requestRelativePath -RequestApiVersion $requestApiVersion
    $payload = $null
    if ($Body -and $BodyFile) { throw 'Body and BodyFile cannot be used together. Supply inline JSON with -Body or provide a file path with -BodyFile.' }
    if ($BodyFile) {
        $resolvedBodyFile = if([IO.Path]::IsPathRooted($BodyFile)){$BodyFile}else{ Join-Path $script:SessionState.ScriptRoot $BodyFile }
        if (-not (Test-Path -LiteralPath $resolvedBodyFile -PathType Leaf)) { throw "Body file '$resolvedBodyFile' does not exist. Verify the path and try again." }
        $payload = Test-JsonContent -Content (Get-Content -LiteralPath $resolvedBodyFile -Raw) -ContentSource 'body file'
    } elseif ($Body) { $payload = Test-JsonContent -Content $Body -ContentSource 'body parameter' }
    elseif ($operationRequest -and $operationRequest.Body) { $payload = Test-JsonContent -Content $operationRequest.Body -ContentSource 'operation preset body' }
    if (($requestMethod -in $script:Configuration.AllowedBodyMethods) -and -not $payload) { Write-Log -Level 'WARN' -Message "HTTP method '$requestMethod' was supplied without a JSON body." }
    # Keep the initial request and final response separate so the same request
    # path works for both synchronous and long-running ARM operations.
    $initial = Get-LastPipelineValueSafe -Values @(Invoke-ArmRequestCore -RequestMethod $requestMethod -RequestInfo $requestInfo -Payload $payload -ValidatedHeaders $validatedHeaders)
    $final = Get-LastPipelineValueSafe -Values @(Wait-ArmLongRunningOperation -InitialResponse $initial -InitialRequestInfo $requestInfo -InitialMethod $requestMethod -ValidatedHeaders $validatedHeaders)
    $formatted = Format-ArmResponse -Response $final
    Save-ArmResponse -FormattedContent $formatted
    if ($formatted -ne '') { Write-Output $formatted }
}

$completedSuccessfully = $false
try {
    # Fail fast on mutually exclusive switches before any file, module, or
    # authentication work begins.
    if ($UseManagedIdentity -and $UseDeviceCode) { throw 'UseManagedIdentity and UseDeviceCode cannot be used together.' }
    if ($PreferBundledModules -and $PreferInstalledModules) { throw 'PreferBundledModules and PreferInstalledModules cannot be used together.' }
    if ($Operation -and ($PSBoundParameters.ContainsKey('Uri') -or $PSBoundParameters.ContainsKey('RelativePath'))) { throw 'Operation cannot be combined with Uri or RelativePath. Use one request mode at a time.' }
    if ($OperationParameters -and -not $Operation) { throw 'OperationParameters requires Operation.' }
    if ($ApiVersions -and -not $Operation) { throw 'ApiVersions requires Operation.' }
    if ($ShowOperationDetails -and -not $Operation) { throw 'ShowOperationDetails requires Operation.' }
    Initialize-Environment
    $isRequest = ($PSBoundParameters.ContainsKey('Uri') -or $PSBoundParameters.ContainsKey('RelativePath') -or ($Operation -and -not $ListOperations -and -not $ShowOperationDetails -and -not $ApiVersions))
    $requiresImportedModules = $ShowContext -or $ApiVersions -or $SelfTest -or $isRequest -or ((-not $ToolVersion) -and (-not $ListOperations) -and (-not $ShowOperationDetails) -and (-not $ShowBundledModuleVersions) -and (-not $ShowResolvedModuleVersions))
    if ($ToolVersion) { Write-Output $script:Configuration.Version }
    if ($ListOperations) { Show-ArmOperationPresetCatalog }
    if ($ShowBundledModuleVersions) { Show-BundledModuleVersionSummary }
    if ($ShowResolvedModuleVersions) { Show-ResolvedModuleVersionSummary }
    if ($ShowOperationDetails -and -not $ApiVersions) { Show-ArmOperationPresetDetails -Name $Operation }
    if (-not $requiresImportedModules) { $completedSuccessfully = $true; return }
    Import-BundledModules | Out-Null
    Initialize-AzProcessSecurity
    Test-AuthenticodeIfRequested -Paths @($script:ScriptPath)
    $utilityActionSelected = ($ToolVersion -or $ShowBundledModuleVersions -or $ShowResolvedModuleVersions -or $SelfTest -or $ListOperations -or $ShowOperationDetails -or $ApiVersions)
    $requiresAuthentication = $ShowContext -or $isRequest -or $ApiVersions -or (-not $utilityActionSelected)
    if ($requiresAuthentication) {
        $context = Get-LastPipelineValueSafe -Values @(Connect-ArmClientPs)
        if ($ShowContext -or ((-not $isRequest) -and (-not $SelfTest) -and (-not $ShowBundledModuleVersions) -and (-not $ShowResolvedModuleVersions) -and (-not $ListOperations) -and (-not $ShowOperationDetails) -and (-not $ApiVersions))) {
            Write-Output ($context | ConvertTo-Json -Depth 10)
        }
    }
    if ($ShowOperationDetails) { Show-ArmOperationPresetDetails -Name $Operation -IncludeApiVersions:$ApiVersions }
    elseif ($ApiVersions) { Show-ArmOperationApiVersions -Name $Operation }
    if ($SelfTest) { Invoke-ArmClientSelfTest }
    if ($isRequest) { Invoke-ArmRequest }
    $completedSuccessfully = $true
} catch { Write-Log -Level 'ERROR' -Message $_.Exception.Message; throw } finally { if ($script:SessionState.ShouldClearContext -and ($script:SessionState.AuthenticatedByScript -or (-not $NoLogin))) { try { Clear-ArmClientPsContext } catch { Write-Log -Level 'WARN' -Message 'Context cleanup encountered an error.' -Data $_.Exception.Message } }; if ($completedSuccessfully) { Write-Log -Level 'INFO' -Message ('{0} completed successfully.' -f $script:Configuration.ToolName) } }
