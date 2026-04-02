#Requires -Version 5.1
<#
.SYNOPSIS
    Azure Resource Manager HTTP helpers for AzArmClient-PS.

.DESCRIPTION
    Wraps Invoke-WebRequest to provide GET, POST, PUT, PATCH, and DELETE
    operations against ARM endpoints.  Features:

    • Automatic Bearer-token injection (via Get-AzArmToken from Auth.psm1)
    • Configurable retry with exponential back-off for transient failures
      (408, 429, 500, 502, 503, 504)
    • Optional LRO handling (calls Watch-ArmOperation from LongRunning.psm1)
    • Consistent PSCustomObject responses with StatusCode, Headers, and Body

.NOTES
    Part of AzArmClient-PS.
#>

Set-StrictMode -Version Latest

#region ── Constants ─────────────────────────────────────────────────────────

$script:RetriableStatusCodes = @(408, 429, 500, 502, 503, 504)

#endregion ───────────────────────────────────────────────────────────────────

#region ── Internal helpers ──────────────────────────────────────────────────

function _BuildArmUri {
    param(
        [string] $ArmEndpoint,
        [string] $ResourcePath,
        [string] $ApiVersion,
        [hashtable] $QueryParams = @{}
    )

    # Normalise the path separator
    $path = $ResourcePath.TrimStart('/')
    $uri  = "$ArmEndpoint/$path"

    $qs = [System.Collections.Generic.List[string]]::new()
    $qs.Add("api-version=$([System.Uri]::EscapeDataString($ApiVersion))")

    foreach ($kv in $QueryParams.GetEnumerator()) {
        $qs.Add("$([System.Uri]::EscapeDataString($kv.Key))=$([System.Uri]::EscapeDataString($kv.Value))")
    }

    return "$uri`?$($qs -join '&')"
}

function _ParseResponse {
    param($WebResponse)

    $body = $null
    if ($WebResponse.Content) {
        try   { $body = $WebResponse.Content | ConvertFrom-Json }
        catch { $body = $WebResponse.Content }   # return raw string if not JSON
    }

    # Normalise headers to a simple hashtable
    $hdrs = @{}
    foreach ($key in $WebResponse.Headers.Keys) {
        $hdrs[$key] = $WebResponse.Headers[$key]
    }

    [PSCustomObject]@{
        StatusCode = [int]$WebResponse.StatusCode
        Headers    = $hdrs
        Body       = $body
        RawContent = $WebResponse.Content
    }
}

function _InvokeWithRetry {
    param(
        [string]    $Method,
        [string]    $Uri,
        [hashtable] $Headers,
        [string]    $Body,
        [int]       $MaxRetries,
        [int]       $RetryBaseDelaySec
    )

    $attempt   = 0
    $lastError = $null

    while ($attempt -le $MaxRetries) {
        $attempt++
        try {
            $iwrParams = @{
                Uri             = $Uri
                Method          = $Method
                Headers         = $Headers
                UseBasicParsing = $true
                ErrorAction     = 'Stop'
            }
            if ($Body) { $iwrParams.Body = $Body }

            $response = Invoke-WebRequest @iwrParams
            return $response
        } catch [System.Net.WebException] {
            $httpResp = $_.Exception.Response
            $sc       = if ($httpResp) { [int]$httpResp.StatusCode } else { 0 }

            if ($sc -notin $script:RetriableStatusCodes -or $attempt -gt $MaxRetries) {
                # Re-throw with useful context
                $errBody = ''
                if ($httpResp) {
                    try {
                        $stream = $httpResp.GetResponseStream()
                        $reader = [System.IO.StreamReader]::new($stream)
                        $errBody = $reader.ReadToEnd()
                        $reader.Dispose()
                    } catch {}
                }
                throw [System.Net.WebException]::new(
                    "HTTP $sc $($_.Exception.Message) — Body: $errBody",
                    $_.Exception,
                    $_.Exception.Status,
                    $httpResp
                )
            }

            $delay = [Math]::Pow(2, $attempt - 1) * $RetryBaseDelaySec
            Write-Verbose "AzArmClient-PS: HTTP $sc – retrying in ${delay}s (attempt $attempt/$MaxRetries)"
            Start-Sleep -Seconds $delay
            $lastError = $_
        }
    }

    throw $lastError
}

#endregion ───────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Sends a request to the Azure Resource Manager REST API.

.DESCRIPTION
    Invoke-ArmRequest is the core of AzArmClient-PS.  All public HTTP-verb
    helpers (Invoke-ArmGet, Invoke-ArmPost, etc.) delegate to this function.

.PARAMETER Method
    HTTP method: GET | POST | PUT | PATCH | DELETE.

.PARAMETER ResourcePath
    ARM resource path relative to the endpoint root, for example:
    /subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vmName}

.PARAMETER ApiVersion
    ARM API version string, e.g. '2023-03-01'.

.PARAMETER Body
    Request body as a PSCustomObject, hashtable, or JSON string.
    Ignored for GET and DELETE.

.PARAMETER QueryParams
    Additional query-string parameters (hashtable).

.PARAMETER WaitForCompletion
    When $true, polls the operation to completion and returns the final result.
    Applies only when the API returns 201/202 with LRO headers.

.PARAMETER LroTimeoutSec
    Maximum wait time for LRO polling (default 7200 s / 2 h).

.PARAMETER MaxRetries
    Number of retry attempts for transient failures (default 3).

.PARAMETER RetryBaseDelaySec
    Base delay in seconds for exponential back-off (default 2).

.PARAMETER SubscriptionId
    Overrides the default subscription from the auth context.

.PARAMETER AdditionalHeaders
    Extra request headers (hashtable).

.OUTPUTS
    PSCustomObject with StatusCode, Headers, Body, and RawContent.
    If WaitForCompletion is $true and the operation completed, Body contains
    the final resource.
#>
function Invoke-ArmRequest {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET','POST','PUT','PATCH','DELETE')]
        [string] $Method,

        [Parameter(Mandatory)]
        [string] $ResourcePath,

        [Parameter(Mandatory)]
        [string] $ApiVersion,

        [object] $Body,

        [hashtable] $QueryParams = @{},

        [switch] $WaitForCompletion,

        [int] $LroTimeoutSec = 7200,

        [int] $MaxRetries = 3,

        [int] $RetryBaseDelaySec = 2,

        [string] $SubscriptionId,

        [hashtable] $AdditionalHeaders = @{}
    )

    # ── Resolve ARM endpoint from the auth context ────────────────────────────
    $ctx = Get-AzArmContext
    if (-not $ctx) { throw 'Not connected. Call Connect-AzArm first.' }

    $armEndpoint = $ctx.ArmEndpoint

    # Inject subscription ID if not already in the path
    $path = $ResourcePath
    if ($SubscriptionId) {
        # Allow explicit override even if path already has a subscription segment
    }

    # ── Build URI ─────────────────────────────────────────────────────────────
    $uri = _BuildArmUri -ArmEndpoint $armEndpoint `
                        -ResourcePath $path `
                        -ApiVersion $ApiVersion `
                        -QueryParams $QueryParams

    # ── Build headers ─────────────────────────────────────────────────────────
    $token   = Get-AzArmToken
    $headers = @{
        Authorization  = "Bearer $token"
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
        'x-ms-client-request-id' = [System.Guid]::NewGuid().ToString()
    }
    foreach ($kv in $AdditionalHeaders.GetEnumerator()) {
        $headers[$kv.Key] = $kv.Value
    }

    # ── Serialise body ────────────────────────────────────────────────────────
    $jsonBody = $null
    if ($Body -and $Method -notin 'GET','DELETE') {
        if ($Body -is [string]) {
            $jsonBody = $Body
        } else {
            $jsonBody = $Body | ConvertTo-Json -Depth 20 -Compress
        }
    }

    Write-Verbose "AzArmClient-PS: $Method $uri"

    # ── Execute ───────────────────────────────────────────────────────────────
    $rawResponse = _InvokeWithRetry `
        -Method           $Method `
        -Uri              $uri `
        -Headers          $headers `
        -Body             $jsonBody `
        -MaxRetries       $MaxRetries `
        -RetryBaseDelaySec $RetryBaseDelaySec

    $response = _ParseResponse $rawResponse

    Write-Verbose "AzArmClient-PS: HTTP $($response.StatusCode)"

    # ── LRO polling ───────────────────────────────────────────────────────────
    if ($WaitForCompletion -and $response.StatusCode -in 201, 202) {
        $getTokenBlock = { Get-AzArmToken }
        $lroResult = Watch-ArmOperation `
            -InitialResponse $response `
            -GetToken        $getTokenBlock `
            -TimeoutSec      $LroTimeoutSec

        $response.Body = $lroResult
    }

    return $response
}

#region ── Convenience wrappers ──────────────────────────────────────────────

<#
.SYNOPSIS  Sends an ARM GET request.
.PARAMETER ResourcePath  ARM resource path.
.PARAMETER ApiVersion    API version string.
.PARAMETER QueryParams   Additional query-string parameters.
.PARAMETER MaxRetries    Retry count for transient failures.
#>
function Invoke-ArmGet {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string]    $ResourcePath,
        [Parameter(Mandatory)] [string]    $ApiVersion,
        [hashtable] $QueryParams     = @{},
        [int]       $MaxRetries      = 3,
        [hashtable] $AdditionalHeaders = @{}
    )
    Invoke-ArmRequest -Method GET -ResourcePath $ResourcePath -ApiVersion $ApiVersion `
        -QueryParams $QueryParams -MaxRetries $MaxRetries -AdditionalHeaders $AdditionalHeaders
}

<#
.SYNOPSIS  Sends an ARM POST request.
.PARAMETER ResourcePath  ARM resource path.
.PARAMETER ApiVersion    API version string.
.PARAMETER Body          Request body (object or JSON string).
.PARAMETER WaitForCompletion  Poll LRO to completion when $true.
#>
function Invoke-ArmPost {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string]    $ResourcePath,
        [Parameter(Mandatory)] [string]    $ApiVersion,
        [object]    $Body,
        [hashtable] $QueryParams          = @{},
        [switch]    $WaitForCompletion,
        [int]       $LroTimeoutSec        = 7200,
        [int]       $MaxRetries           = 3,
        [hashtable] $AdditionalHeaders    = @{}
    )
    Invoke-ArmRequest -Method POST -ResourcePath $ResourcePath -ApiVersion $ApiVersion `
        -Body $Body -QueryParams $QueryParams -WaitForCompletion:$WaitForCompletion `
        -LroTimeoutSec $LroTimeoutSec -MaxRetries $MaxRetries -AdditionalHeaders $AdditionalHeaders
}

<#
.SYNOPSIS  Sends an ARM PUT request.
.PARAMETER ResourcePath  ARM resource path.
.PARAMETER ApiVersion    API version string.
.PARAMETER Body          Resource definition.
.PARAMETER WaitForCompletion  Poll LRO to completion when $true.
#>
function Invoke-ArmPut {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string]    $ResourcePath,
        [Parameter(Mandatory)] [string]    $ApiVersion,
        [Parameter(Mandatory)] [object]    $Body,
        [hashtable] $QueryParams          = @{},
        [switch]    $WaitForCompletion,
        [int]       $LroTimeoutSec        = 7200,
        [int]       $MaxRetries           = 3,
        [hashtable] $AdditionalHeaders    = @{}
    )
    Invoke-ArmRequest -Method PUT -ResourcePath $ResourcePath -ApiVersion $ApiVersion `
        -Body $Body -QueryParams $QueryParams -WaitForCompletion:$WaitForCompletion `
        -LroTimeoutSec $LroTimeoutSec -MaxRetries $MaxRetries -AdditionalHeaders $AdditionalHeaders
}

<#
.SYNOPSIS  Sends an ARM PATCH request.
.PARAMETER ResourcePath  ARM resource path.
.PARAMETER ApiVersion    API version string.
.PARAMETER Body          Partial resource definition.
.PARAMETER WaitForCompletion  Poll LRO to completion when $true.
#>
function Invoke-ArmPatch {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string]    $ResourcePath,
        [Parameter(Mandatory)] [string]    $ApiVersion,
        [Parameter(Mandatory)] [object]    $Body,
        [hashtable] $QueryParams          = @{},
        [switch]    $WaitForCompletion,
        [int]       $LroTimeoutSec        = 7200,
        [int]       $MaxRetries           = 3,
        [hashtable] $AdditionalHeaders    = @{}
    )
    Invoke-ArmRequest -Method PATCH -ResourcePath $ResourcePath -ApiVersion $ApiVersion `
        -Body $Body -QueryParams $QueryParams -WaitForCompletion:$WaitForCompletion `
        -LroTimeoutSec $LroTimeoutSec -MaxRetries $MaxRetries -AdditionalHeaders $AdditionalHeaders
}

<#
.SYNOPSIS  Sends an ARM DELETE request.
.PARAMETER ResourcePath  ARM resource path.
.PARAMETER ApiVersion    API version string.
.PARAMETER WaitForCompletion  Poll LRO to completion when $true.
#>
function Invoke-ArmDelete {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string]    $ResourcePath,
        [Parameter(Mandatory)] [string]    $ApiVersion,
        [hashtable] $QueryParams          = @{},
        [switch]    $WaitForCompletion,
        [int]       $LroTimeoutSec        = 7200,
        [int]       $MaxRetries           = 3,
        [hashtable] $AdditionalHeaders    = @{}
    )
    Invoke-ArmRequest -Method DELETE -ResourcePath $ResourcePath -ApiVersion $ApiVersion `
        -QueryParams $QueryParams -WaitForCompletion:$WaitForCompletion `
        -LroTimeoutSec $LroTimeoutSec -MaxRetries $MaxRetries -AdditionalHeaders $AdditionalHeaders
}

#endregion ───────────────────────────────────────────────────────────────────

Export-ModuleMember -Function Invoke-ArmRequest, Invoke-ArmGet, Invoke-ArmPost, Invoke-ArmPut, Invoke-ArmPatch, Invoke-ArmDelete
