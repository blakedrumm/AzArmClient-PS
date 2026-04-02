#Requires -Version 5.1
<#
.SYNOPSIS
    Long-running operation (LRO) polling for Azure Resource Manager.

.DESCRIPTION
    Implements the Azure REST API long-running operation pattern described at
    https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/async-operations

    After a mutating ARM call (PUT / PATCH / POST / DELETE) returns HTTP 201 or
    202, the response may carry one of these headers:

      • Azure-AsyncOperation  – poll until the operation body contains a terminal
                                 status (Succeeded / Failed / Canceled).
      • Location              – poll until HTTP 200 (or 204).
      • Retry-After           – honour this delay (capped at MaxPollIntervalSec).

    Watch-ArmOperation handles both patterns and returns the final body on
    success, or throws on failure/timeout.

.NOTES
    Part of AzArmClient-PS.
#>

Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Polls an Azure LRO until it reaches a terminal state.

.PARAMETER InitialResponse
    The [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject] / PSCustomObject
    returned by Invoke-ArmRequest.  Must expose .StatusCode and .Headers.

.PARAMETER GetToken
    A scriptblock { } that returns a valid Bearer token string.

.PARAMETER TimeoutSec
    Maximum total poll time in seconds (default 7200 / 2 hours).

.PARAMETER DefaultPollIntervalSec
    Fallback poll interval when no Retry-After header is present (default 15 s).

.PARAMETER MaxPollIntervalSec
    Upper bound on any single poll delay (default 60 s).

.OUTPUTS
    PSCustomObject – the final operation result body (may be $null for 204).
#>
function Watch-ArmOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $InitialResponse,

        [Parameter(Mandatory)]
        [scriptblock] $GetToken,

        [int] $TimeoutSec             = 7200,
        [int] $DefaultPollIntervalSec = 15,
        [int] $MaxPollIntervalSec     = 60
    )

    $statusCode = [int]$InitialResponse.StatusCode

    # Nothing to poll for synchronous successes
    if ($statusCode -notin 201, 202) { return $InitialResponse.Body }

    $asyncUri  = $InitialResponse.Headers['Azure-AsyncOperation']
    $locationUri = $InitialResponse.Headers['Location']

    if (-not $asyncUri -and -not $locationUri) {
        # No polling header – treat the initial response as final
        return $InitialResponse.Body
    }

    # Prefer Azure-AsyncOperation when both are present
    $useAsync = [bool]$asyncUri
    $pollUri  = if ($useAsync) { $asyncUri } else { $locationUri }

    $deadline  = (Get-Date).AddSeconds($TimeoutSec)
    $iteration = 0

    Write-Verbose "AzArmClient-PS: Starting LRO poll on: $pollUri"

    while ((Get-Date) -lt $deadline) {
        $iteration++

        # --- Poll ---
        $token   = & $GetToken
        $headers = @{
            Authorization = "Bearer $token"
            'Content-Type' = 'application/json'
        }

        try {
            $pollResp = Invoke-WebRequest -Uri $pollUri -Method GET -Headers $headers `
                            -UseBasicParsing -ErrorAction Stop
        } catch [System.Net.WebException] {
            $httpEx = $_.Exception.Response
            if ($httpEx) {
                $sc = [int]$httpEx.StatusCode
                throw "LRO poll failed with HTTP $sc on '$pollUri'."
            }
            throw
        }

        $pollCode = [int]$pollResp.StatusCode

        # ── Azure-AsyncOperation pattern ──────────────────────────────────────
        if ($useAsync) {
            if ($pollCode -ge 200 -and $pollCode -le 299) {
                $body = $pollResp.Content | ConvertFrom-Json

                $opStatus = $body.status
                Write-Verbose "AzArmClient-PS: LRO iter=$iteration status=$opStatus"

                if ($opStatus -eq 'Succeeded') {
                    # If there is a Location header, do one final GET for the resource
                    if ($locationUri) {
                        $finalToken = & $GetToken
                        $finalHdrs  = @{ Authorization = "Bearer $finalToken" }
                        $finalResp  = Invoke-WebRequest -Uri $locationUri -Method GET `
                                          -Headers $finalHdrs -UseBasicParsing -ErrorAction Stop
                        if ([int]$finalResp.StatusCode -eq 204) { return $null }
                        return $finalResp.Content | ConvertFrom-Json
                    }
                    return $body
                }

                if ($opStatus -in 'Failed', 'Canceled') {
                    $errMsg = try { $body.error.message } catch { 'No error message returned.' }
                    throw "Long-running operation $opStatus. $errMsg"
                }

                # Still in progress – fall through to sleep
            }
        }
        # ── Location pattern ──────────────────────────────────────────────────
        else {
            Write-Verbose "AzArmClient-PS: LRO iter=$iteration httpStatus=$pollCode"

            if ($pollCode -eq 204) { return $null }

            if ($pollCode -ge 200 -and $pollCode -le 299) {
                return $pollResp.Content | ConvertFrom-Json
            }

            if ($pollCode -ge 400) {
                throw "LRO Location poll returned HTTP $pollCode."
            }
            # 202 / 3xx – continue polling
        }

        # --- Back-off ---
        $retryAfter = $DefaultPollIntervalSec
        if ($pollResp.Headers['Retry-After']) {
            $retryAfter = [Math]::Min([int]$pollResp.Headers['Retry-After'], $MaxPollIntervalSec)
        }
        $retryAfter = [Math]::Min($retryAfter, $MaxPollIntervalSec)

        Write-Verbose "AzArmClient-PS: LRO sleeping ${retryAfter}s (iter=$iteration)"
        Start-Sleep -Seconds $retryAfter
    }

    throw "Long-running operation timed out after $TimeoutSec seconds. Last poll URI: $pollUri"
}

Export-ModuleMember -Function Watch-ArmOperation
