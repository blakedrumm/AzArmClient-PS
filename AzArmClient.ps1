#Requires -Version 5.1
<#
.SYNOPSIS
    AzArmClient-PS – Secure PowerShell Azure Resource Manager REST client.

.DESCRIPTION
    Entry-point script for AzArmClient-PS.  Dot-source this file to load the
    full public API into the current session:

        . .\AzArmClient.ps1

    Or pass -WhatIf to perform a dry-run integrity check without importing
    anything.

    ╔══════════════════════════════════════════════════════════╗
    ║  Public functions exported after dot-sourcing            ║
    ╠══════════════════════════════════════════════════════════╣
    ║  Authentication                                          ║
    ║    Connect-AzArm          – authenticate to ARM          ║
    ║    Disconnect-AzArm       – clear cached credentials     ║
    ║    Get-AzArmContext        – inspect current auth context ║
    ║  HTTP verbs                                              ║
    ║    Invoke-ArmRequest      – generic ARM request          ║
    ║    Invoke-ArmGet          – GET wrapper                  ║
    ║    Invoke-ArmPost         – POST wrapper                 ║
    ║    Invoke-ArmPut          – PUT wrapper                  ║
    ║    Invoke-ArmPatch        – PATCH wrapper                ║
    ║    Invoke-ArmDelete       – DELETE wrapper               ║
    ║  Long-running operations                                 ║
    ║    Watch-ArmOperation     – poll an LRO to completion    ║
    ║  Logging                                                 ║
    ║    Write-ArmLog           – emit structured log entry    ║
    ║    Set-ArmLogLevel        – change minimum log level     ║
    ║    Set-ArmLogFile         – configure file sink          ║
    ╚══════════════════════════════════════════════════════════╝

.PARAMETER SkipIntegrityCheck
    Bypasses the module hash verification step.  Use only in controlled
    environments where you manage module provenance yourself.

.PARAMETER LogLevel
    Initial log level: DEBUG | INFO | WARN | ERROR  (default: INFO).

.PARAMETER LogFile
    Optional path to a log file.

.EXAMPLE
    # Interactive login – public cloud
    . .\AzArmClient.ps1
    Connect-AzArm -Method Interactive
    $vms = Invoke-ArmGet `
               -ResourcePath '/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Compute/virtualMachines' `
               -ApiVersion   '2023-07-01'
    $vms.Body.value | Select-Object -ExpandProperty name

.EXAMPLE
    # Service principal with client secret
    . .\AzArmClient.ps1
    $secret = Read-Host 'Client secret' -AsSecureString
    Connect-AzArm -TenantId $tenantId -ClientId $appId -ClientSecret $secret
    $resp = Invoke-ArmGet `
               -ResourcePath "/subscriptions/$subId/resourceGroups" `
               -ApiVersion   '2021-04-01'
    $resp.Body.value.name

.EXAMPLE
    # Service principal with certificate (thumbprint lookup)
    . .\AzArmClient.ps1
    Connect-AzArm -TenantId $tenantId -ClientId $appId -CertificateThumbprint 'ABCDEF...'

.EXAMPLE
    # Managed Identity (system-assigned)
    . .\AzArmClient.ps1
    Connect-AzArm

.EXAMPLE
    # Create a resource and wait for LRO to complete
    . .\AzArmClient.ps1
    Connect-AzArm -TenantId $tenantId -ClientId $appId -ClientSecret $secret
    $body = @{
        location   = 'eastus'
        properties = @{ createMode = 'Default' }
    }
    $resp = Invoke-ArmPut `
               -ResourcePath "/subscriptions/$subId/resourceGroups/myRG/providers/Microsoft.Sql/servers/mySrv" `
               -ApiVersion   '2022-05-01-preview' `
               -Body         $body `
               -WaitForCompletion

.NOTES
    Author  : Blake Drumm
    Project : https://github.com/blakedrumm/AzArmClient-PS
    License : MIT
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch] $SkipIntegrityCheck,

    [ValidateSet('DEBUG','INFO','WARN','ERROR')]
    [string] $LogLevel = 'INFO',

    [string] $LogFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Locate module files ───────────────────────────────────────────────

$script:RootPath    = $PSScriptRoot
$script:ModulesPath = Join-Path $script:RootPath 'Modules'

if (-not (Test-Path $script:ModulesPath -PathType Container)) {
    throw "Modules directory not found at '$($script:ModulesPath)'. " +
          "Ensure you have a complete AzArmClient-PS distribution."
}

$script:ModuleFiles = @(
    'Logging.psm1',
    'Integrity.psm1',
    'Auth.psm1',
    'ArmRequests.psm1',
    'LongRunning.psm1'
)

#endregion ───────────────────────────────────────────────────────────────────

#region ── Bootstrap: load Logging first (needed for all subsequent messages) ─

$loggingModule = Join-Path $script:ModulesPath 'Logging.psm1'
if (-not (Test-Path $loggingModule -PathType Leaf)) {
    throw "Critical module missing: '$loggingModule'"
}
Import-Module $loggingModule -Force -DisableNameChecking

Set-ArmLogLevel -Level $LogLevel
if ($LogFile) { Set-ArmLogFile -Path $LogFile }

Write-ArmLog -Level INFO -Message 'AzArmClient-PS initialising'

#endregion ───────────────────────────────────────────────────────────────────

#region ── Integrity check ───────────────────────────────────────────────────

if (-not $SkipIntegrityCheck) {
    $integrityModule = Join-Path $script:ModulesPath 'Integrity.psm1'
    if (-not (Test-Path $integrityModule -PathType Leaf)) {
        Write-ArmLog -Level WARN -Message "Integrity module not found – skipping hash check."
    } else {
        Import-Module $integrityModule -Force -DisableNameChecking

        $manifestPath = Join-Path $script:RootPath 'modules.sha256'
        if (Test-Path $manifestPath -PathType Leaf) {
            Write-ArmLog -Level DEBUG -Message 'Verifying module integrity...'
            if ($PSCmdlet.ShouldProcess($manifestPath, 'Verify module integrity')) {
                try {
                    Test-ModuleIntegrity -RootPath $script:RootPath -ManifestPath $manifestPath
                    Write-ArmLog -Level DEBUG -Message 'Module integrity OK'
                } catch {
                    Write-ArmLog -Level ERROR -Message "Integrity check failed: $_"
                    throw
                }
            }
        } else {
            Write-ArmLog -Level WARN -Message "No integrity manifest found at '$manifestPath'. " +
                "Run Build-AzArmClient.ps1 to generate one."
        }
    }
} else {
    Write-ArmLog -Level WARN -Message 'Integrity check skipped (-SkipIntegrityCheck).'
}

#endregion ───────────────────────────────────────────────────────────────────

#region ── Load remaining modules ────────────────────────────────────────────

foreach ($modFile in $script:ModuleFiles) {
    $fullPath = Join-Path $script:ModulesPath $modFile
    if (-not (Test-Path $fullPath -PathType Leaf)) {
        throw "Required module file missing: '$fullPath'"
    }
    # Logging and Integrity may already be loaded
    Import-Module $fullPath -Force -DisableNameChecking
    Write-ArmLog -Level DEBUG -Message "Loaded module" -Data @{ File = $modFile }
}

#endregion ───────────────────────────────────────────────────────────────────

Write-ArmLog -Level INFO -Message 'AzArmClient-PS ready. Call Connect-AzArm to authenticate.'
