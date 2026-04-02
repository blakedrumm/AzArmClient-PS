#Requires -Version 5.1
<#
.SYNOPSIS
    Secure Azure authentication helpers for AzArmClient-PS.

.DESCRIPTION
    Provides Connect-AzArm (authenticates and caches a token context) and
    Get-AzArmToken (returns a valid Bearer token, refreshing automatically).

    Supported authentication methods
    ─────────────────────────────────
    • ServicePrincipalSecret  – client-id + client-secret
    • ServicePrincipalCert    – client-id + X.509 certificate
    • ManagedIdentity         – system-assigned or user-assigned MSI
    • Interactive             – device-code or interactive browser login
                                (requires Az.Accounts)

.NOTES
    Part of AzArmClient-PS.
    Tokens obtained via Az.Accounts are cached by that library; for the
    ServicePrincipal* flows we cache only the expiry time and re-acquire
    100 seconds before the token expires.
#>

Set-StrictMode -Version Latest

#region ── Internal state ─────────────────────────────────────────────────────

$script:Context = $null   # hashtable populated by Connect-AzArm

#endregion ───────────────────────────────────────────────────────────────────

#region ── Internal helpers ──────────────────────────────────────────────────

function _RequireModule {
    param([string] $Name)
    if (-not (Get-Module -Name $Name -ListAvailable)) {
        throw "Required module '$Name' is not available. " +
              "Run Build-AzArmClient.ps1 to install bundled modules."
    }
    if (-not (Get-Module -Name $Name)) {
        Import-Module -Name $Name -ErrorAction Stop
    }
}

function _GetAzEndpoints {
    param([string] $Environment)
    # Returns the Resource Manager endpoint and authority for each cloud.
    switch ($Environment) {
        'AzureCloud'        {
            @{
                ArmEndpoint  = 'https://management.azure.com'
                LoginBase    = 'https://login.microsoftonline.com'
                ArmScope     = 'https://management.azure.com/.default'
            }
        }
        'AzureChinaCloud'   {
            @{
                ArmEndpoint  = 'https://management.chinacloudapi.cn'
                LoginBase    = 'https://login.partner.microsoftonline.cn'
                ArmScope     = 'https://management.chinacloudapi.cn/.default'
            }
        }
        'AzureUSGovernment' {
            @{
                ArmEndpoint  = 'https://management.usgovcloudapi.net'
                LoginBase    = 'https://login.microsoftonline.us'
                ArmScope     = 'https://management.usgovcloudapi.net/.default'
            }
        }
        default {
            throw "Unknown Azure environment '$Environment'. " +
                  "Valid values: AzureCloud, AzureChinaCloud, AzureUSGovernment."
        }
    }
}

# Low-level OAuth 2.0 client-credentials token request (no Az dependency)
function _GetTokenClientSecret {
    param(
        [string] $LoginBase,
        [string] $TenantId,
        [string] $ClientId,
        [securestring] $ClientSecret,
        [string] $Scope
    )

    $plainSecret = [System.Net.NetworkCredential]::new('', $ClientSecret).Password

    $body = @{
        grant_type    = 'client_credentials'
        client_id     = $ClientId
        client_secret = $plainSecret
        scope         = $Scope
    }

    $uri  = "$LoginBase/$TenantId/oauth2/v2.0/token"
    $resp = Invoke-RestMethod -Uri $uri -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop

    [PSCustomObject]@{
        AccessToken = $resp.access_token
        ExpiresOn   = (Get-Date).AddSeconds([int]$resp.expires_in)
    }
}

# Certificate-based client-credentials (JWT assertion)
function _GetTokenClientCert {
    param(
        [string] $LoginBase,
        [string] $TenantId,
        [string] $ClientId,
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [string] $Scope
    )

    # Build JWT header + claims
    $thumbprintBytes = [System.Convert]::FromHexString($Certificate.Thumbprint)
    $x5t             = ([System.Convert]::ToBase64String($thumbprintBytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_')

    $now = [System.DateTimeOffset]::UtcNow
    $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = $x5t } |
              ConvertTo-Json -Compress
    $claims = @{
        aud = "$LoginBase/$TenantId/oauth2/v2.0/token"
        iss = $ClientId
        sub = $ClientId
        jti = [System.Guid]::NewGuid().ToString()
        nbf = $now.ToUnixTimeSeconds()
        exp = $now.AddMinutes(10).ToUnixTimeSeconds()
    } | ConvertTo-Json -Compress

    $enc     = [System.Text.Encoding]::UTF8
    $b64Hdr  = [System.Convert]::ToBase64String($enc.GetBytes($header)).TrimEnd('=').Replace('+','-').Replace('/','_')
    $b64Clm  = [System.Convert]::ToBase64String($enc.GetBytes($claims)).TrimEnd('=').Replace('+','-').Replace('/','_')
    $toSign  = "$b64Hdr.$b64Clm"

    $rsa       = $Certificate.GetRSAPrivateKey()
    $signature = $rsa.SignData($enc.GetBytes($toSign),
                               [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                               [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $b64Sig    = [System.Convert]::ToBase64String($signature).TrimEnd('=').Replace('+','-').Replace('/','_')

    $jwt  = "$toSign.$b64Sig"
    $body = @{
        grant_type             = 'client_credentials'
        client_id              = $ClientId
        client_assertion_type  = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion       = $jwt
        scope                  = $Scope
    }

    $uri  = "$LoginBase/$TenantId/oauth2/v2.0/token"
    $resp = Invoke-RestMethod -Uri $uri -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop

    [PSCustomObject]@{
        AccessToken = $resp.access_token
        ExpiresOn   = (Get-Date).AddSeconds([int]$resp.expires_in)
    }
}

# IMDS-based token for Managed Identity
function _GetTokenMsi {
    param(
        [string] $Resource,          # e.g. 'https://management.azure.com/'
        [string] $ClientId           # optional user-assigned MSI client-id
    )

    $uri = 'http://169.254.169.254/metadata/identity/oauth2/token' +
           "?api-version=2019-08-01&resource=$([System.Uri]::EscapeDataString($Resource))"
    if ($ClientId) { $uri += "&client_id=$([System.Uri]::EscapeDataString($ClientId))" }

    $resp = Invoke-RestMethod -Uri $uri -Method GET -Headers @{ Metadata = 'true' } -ErrorAction Stop

    [PSCustomObject]@{
        AccessToken = $resp.access_token
        ExpiresOn   = (Get-Date).AddSeconds([int]$resp.expires_in)
    }
}

#endregion ───────────────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Authenticates to Azure and stores the session context for subsequent calls.

.PARAMETER Method
    Authentication method:
    ServicePrincipalSecret | ServicePrincipalCert | ManagedIdentity | Interactive

.PARAMETER TenantId
    Azure AD tenant ID.  Required for ServicePrincipal* and Interactive methods.

.PARAMETER ClientId
    Application (client) ID.  Required for ServicePrincipal* methods.
    Optional for user-assigned ManagedIdentity (pass MSI client-id).

.PARAMETER ClientSecret
    Client secret as a SecureString.  Required for ServicePrincipalSecret.

.PARAMETER Certificate
    X.509 certificate object with private key.  Required for ServicePrincipalCert.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate in the local certificate store (alternative to -Certificate).

.PARAMETER SubscriptionId
    Default subscription for ARM requests.  Can also be specified per-request.

.PARAMETER Environment
    Azure cloud: AzureCloud (default), AzureChinaCloud, AzureUSGovernment.
#>
function Connect-AzArm {
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ServicePrincipalSecret')]
        [Parameter(Mandatory, ParameterSetName = 'ServicePrincipalCert')]
        [Parameter(Mandatory, ParameterSetName = 'ServicePrincipalCertThumbprint')]
        [string] $TenantId,

        [Parameter(Mandatory, ParameterSetName = 'ServicePrincipalSecret')]
        [Parameter(Mandatory, ParameterSetName = 'ServicePrincipalCert')]
        [Parameter(Mandatory, ParameterSetName = 'ServicePrincipalCertThumbprint')]
        [string] $ClientId,

        [Parameter(Mandatory, ParameterSetName = 'ServicePrincipalSecret')]
        [securestring] $ClientSecret,

        [Parameter(Mandatory, ParameterSetName = 'ServicePrincipalCert')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        [Parameter(Mandatory, ParameterSetName = 'ServicePrincipalCertThumbprint')]
        [string] $CertificateThumbprint,

        [Parameter(ParameterSetName = 'ManagedIdentity')]
        [string] $MsiClientId,

        [Parameter(ParameterSetName = 'Interactive')]
        [string] $TenantIdInteractive,

        [string] $SubscriptionId,

        [ValidateSet('AzureCloud','AzureChinaCloud','AzureUSGovernment')]
        [string] $Environment = 'AzureCloud'
    )

    $endpoints = _GetAzEndpoints -Environment $Environment

    $method = $PSCmdlet.ParameterSetName

    $ctx = @{
        Method         = $method
        Environment    = $Environment
        Endpoints      = $endpoints
        SubscriptionId = $SubscriptionId
        Token          = $null
        TokenExpiry    = [datetime]::MinValue
    }

    switch ($method) {
        'ServicePrincipalSecret' {
            $ctx.TenantId     = $TenantId
            $ctx.ClientId     = $ClientId
            $ctx.ClientSecret = $ClientSecret
        }
        'ServicePrincipalCert' {
            $ctx.TenantId    = $TenantId
            $ctx.ClientId    = $ClientId
            $ctx.Certificate = $Certificate
        }
        'ServicePrincipalCertThumbprint' {
            $ctx.TenantId    = $TenantId
            $ctx.ClientId    = $ClientId
            # Resolve cert from store now; fail early if not found
            $cert = Get-Item "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
            if (-not $cert) {
                $cert = Get-Item "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
            }
            if (-not $cert) {
                throw "Certificate with thumbprint '$CertificateThumbprint' not found in LocalMachine\My or CurrentUser\My."
            }
            $ctx.Certificate = $cert
            $method = 'ServicePrincipalCert'   # re-use cert flow
        }
        'ManagedIdentity' {
            $ctx.MsiClientId = $MsiClientId
        }
        'Interactive' {
            $ctx.TenantId = $TenantIdInteractive
            _RequireModule 'Az.Accounts'
            $connectParams = @{ Environment = $Environment }
            if ($TenantIdInteractive) { $connectParams.TenantId = $TenantIdInteractive }
            if ($SubscriptionId)      { $connectParams.SubscriptionId = $SubscriptionId }
            Connect-AzAccount @connectParams | Out-Null
        }
    }

    $script:Context = $ctx
    Write-Verbose "AzArmClient-PS: Connected using $method to $($endpoints.ArmEndpoint)"
}

<#
.SYNOPSIS
    Returns a valid Bearer token for the configured Azure environment.

.DESCRIPTION
    Tokens are cached and refreshed automatically 100 seconds before expiry.
    For Interactive sessions the token is retrieved via Get-AzAccessToken
    (Az.Accounts).

.OUTPUTS
    [string] – the raw token value (do not log).
#>
function Get-AzArmToken {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (-not $script:Context) {
        throw 'Not connected. Call Connect-AzArm first.'
    }

    $ctx       = $script:Context
    $nowPlus   = (Get-Date).AddSeconds(100)

    # Reuse cached token if still valid
    if ($ctx.Token -and $ctx.TokenExpiry -gt $nowPlus) {
        return $ctx.Token
    }

    switch ($ctx.Method) {
        'ServicePrincipalSecret' {
            $result = _GetTokenClientSecret `
                -LoginBase    $ctx.Endpoints.LoginBase `
                -TenantId     $ctx.TenantId `
                -ClientId     $ctx.ClientId `
                -ClientSecret $ctx.ClientSecret `
                -Scope        $ctx.Endpoints.ArmScope
            $ctx.Token       = $result.AccessToken
            $ctx.TokenExpiry = $result.ExpiresOn
        }
        'ServicePrincipalCert' {
            $result = _GetTokenClientCert `
                -LoginBase   $ctx.Endpoints.LoginBase `
                -TenantId    $ctx.TenantId `
                -ClientId    $ctx.ClientId `
                -Certificate $ctx.Certificate `
                -Scope       $ctx.Endpoints.ArmScope
            $ctx.Token       = $result.AccessToken
            $ctx.TokenExpiry = $result.ExpiresOn
        }
        'ManagedIdentity' {
            $result = _GetTokenMsi `
                -Resource $ctx.Endpoints.ArmEndpoint + '/' `
                -ClientId $ctx.MsiClientId
            $ctx.Token       = $result.AccessToken
            $ctx.TokenExpiry = $result.ExpiresOn
        }
        'Interactive' {
            _RequireModule 'Az.Accounts'
            $azToken   = Get-AzAccessToken -ResourceUrl $ctx.Endpoints.ArmEndpoint -ErrorAction Stop
            $ctx.Token       = $azToken.Token
            $ctx.TokenExpiry = $azToken.ExpiresOn.LocalDateTime
        }
        default { throw "Unsupported auth method: $($ctx.Method)" }
    }

    return $ctx.Token
}

<#
.SYNOPSIS
    Returns the current context metadata (without the token).
#>
function Get-AzArmContext {
    [CmdletBinding()]
    param()

    if (-not $script:Context) { return $null }

    [PSCustomObject]@{
        Method         = $script:Context.Method
        Environment    = $script:Context.Environment
        ArmEndpoint    = $script:Context.Endpoints.ArmEndpoint
        TenantId       = $script:Context.TenantId
        ClientId       = $script:Context.ClientId
        SubscriptionId = $script:Context.SubscriptionId
        TokenExpiry    = $script:Context.TokenExpiry
    }
}

<#
.SYNOPSIS
    Clears the stored authentication context (removes the cached token).
#>
function Disconnect-AzArm {
    [CmdletBinding()]
    param()

    if ($script:Context -and $script:Context.Method -eq 'Interactive') {
        _RequireModule 'Az.Accounts'
        Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
    }

    $script:Context = $null
    Write-Verbose 'AzArmClient-PS: Disconnected.'
}

Export-ModuleMember -Function Connect-AzArm, Get-AzArmToken, Get-AzArmContext, Disconnect-AzArm
