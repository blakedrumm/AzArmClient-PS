#Requires -Version 5.1
<#
.SYNOPSIS
    Structured logging helper for AzArmClient-PS.

.DESCRIPTION
    Provides Write-ArmLog, which emits colour-coded messages to the host and
    optionally appends them (with timestamps) to a log file.  Log levels:
    DEBUG, INFO, WARN, ERROR.

    Consumers control verbosity via $ArmLogLevel (module-scoped variable) or
    by calling Set-ArmLogLevel.

.NOTES
    Part of AzArmClient-PS.
#>

Set-StrictMode -Version Latest

#region ── Module-level configuration ────────────────────────────────────────

# Ordered severity map  (lower number = more verbose)
$script:LogLevels = [ordered]@{
    DEBUG = 0
    INFO  = 1
    WARN  = 2
    ERROR = 3
}

# Active minimum level (can be overridden with Set-ArmLogLevel)
$script:ActiveLevel = 1   # INFO

# Optional file sink
$script:LogFile = $null

#endregion ───────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Sets the minimum log level written to host / file.

.PARAMETER Level
    One of: DEBUG, INFO, WARN, ERROR.
#>
function Set-ArmLogLevel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('DEBUG','INFO','WARN','ERROR')]
        [string] $Level
    )
    $script:ActiveLevel = $script:LogLevels[$Level]
}

<#
.SYNOPSIS
    Configures an optional file sink for log output.

.PARAMETER Path
    Absolute or relative path to the log file.  The directory must exist.

.PARAMETER Disable
    Clears the file sink (stops writing to file).
#>
function Set-ArmLogFile {
    [CmdletBinding(DefaultParameterSetName = 'Enable')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Enable')]
        [string] $Path,

        [Parameter(Mandatory, ParameterSetName = 'Disable')]
        [switch] $Disable
    )

    if ($PSCmdlet.ParameterSetName -eq 'Disable') {
        $script:LogFile = $null
        return
    }

    # Validate / create parent directory
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
    }

    $script:LogFile = $Path
}

<#
.SYNOPSIS
    Writes a structured, colour-coded log entry.

.PARAMETER Level
    Severity: DEBUG | INFO | WARN | ERROR.

.PARAMETER Message
    Human-readable message body.

.PARAMETER Data
    Optional hashtable of supplementary key/value pairs appended to the line.
#>
function Write-ArmLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('DEBUG','INFO','WARN','ERROR')]
        [string] $Level,

        [Parameter(Mandatory)]
        [string] $Message,

        [hashtable] $Data = @{}
    )

    # Honour minimum level
    if ($script:LogLevels[$Level] -lt $script:ActiveLevel) { return }

    $ts        = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $dataStr   = if ($Data.Count -gt 0) {
        ' ' + (($Data.GetEnumerator() | Sort-Object Name |
                ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' ')
    } else { '' }

    $line = "[$ts] [$Level] $Message$dataStr"

    # Colour map
    $colour = switch ($Level) {
        'DEBUG' { 'Gray'    }
        'INFO'  { 'Cyan'    }
        'WARN'  { 'Yellow'  }
        'ERROR' { 'Red'     }
    }

    Write-Host $line -ForegroundColor $colour

    if ($script:LogFile) {
        try {
            Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
        } catch {
            # Never let logging crash the caller
            Write-Warning "AzArmClient-PS: Failed to write log to '$($script:LogFile)': $_"
        }
    }
}

Export-ModuleMember -Function Write-ArmLog, Set-ArmLogLevel, Set-ArmLogFile
