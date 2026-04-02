# AzArmClient-PS

Secure PowerShell-based Azure Resource Manager REST client with bundled modules,
integrity validation, and support for Azure public and sovereign clouds.

## Features

| Feature | Details |
|---|---|
| **Authentication** | Service Principal (secret or cert), Managed Identity, Interactive device-code |
| **Sovereign clouds** | AzureCloud, AzureChinaCloud, AzureUSGovernment |
| **HTTP verbs** | GET · POST · PUT · PATCH · DELETE |
| **LRO polling** | Azure-AsyncOperation and Location header patterns |
| **Retry logic** | Exponential back-off for 408/429/5xx transient errors |
| **Integrity check** | SHA-256 manifest verifies every module before import |
| **Structured logging** | Colour-coded levels (DEBUG/INFO/WARN/ERROR), optional log file |
| **Build script** | Pins and bundles exact Az module versions; generates zip archive |

---

## Quick start

```powershell
# 1. Dot-source the main script (loads all modules)
. .\AzArmClient.ps1

# 2. Authenticate (choose one method below)

# -- Interactive (requires Az.Accounts) --
Connect-AzArm

# -- Service principal with client secret --
$secret = Read-Host 'Client secret' -AsSecureString
Connect-AzArm -TenantId '<tenantId>' -ClientId '<appId>' -ClientSecret $secret

# -- Service principal with certificate (cert-store lookup) --
Connect-AzArm -TenantId '<tenantId>' -ClientId '<appId>' `
              -CertificateThumbprint '<thumbprint>'

# -- Managed Identity (system-assigned, e.g. on an Azure VM) --
Connect-AzArm

# 3. Call ARM
$resp = Invoke-ArmGet `
            -ResourcePath '/subscriptions/<subId>/resourceGroups' `
            -ApiVersion   '2021-04-01'
$resp.Body.value.name

# 4. Create or update a resource and wait for LRO completion
$body = @{ location = 'eastus'; properties = @{} }
$result = Invoke-ArmPut `
              -ResourcePath '/subscriptions/<subId>/resourceGroups/myRG/providers/...' `
              -ApiVersion   '2023-07-01' `
              -Body         $body `
              -WaitForCompletion
```

---

## Public API

### Authentication

| Function | Description |
|---|---|
| `Connect-AzArm` | Authenticates and stores the session context |
| `Get-AzArmContext` | Returns current context metadata (no token) |
| `Disconnect-AzArm` | Clears the cached context / token |

#### `Connect-AzArm` parameter sets

```
# Service principal – client secret
Connect-AzArm -TenantId <string> -ClientId <string> -ClientSecret <securestring>
              [-SubscriptionId <string>] [-Environment <cloud>]

# Service principal – certificate object
Connect-AzArm -TenantId <string> -ClientId <string> -Certificate <X509Certificate2>
              [-SubscriptionId <string>] [-Environment <cloud>]

# Service principal – certificate thumbprint (resolved from cert store)
Connect-AzArm -TenantId <string> -ClientId <string> -CertificateThumbprint <string>
              [-SubscriptionId <string>] [-Environment <cloud>]

# Managed Identity
Connect-AzArm [-MsiClientId <string>] [-SubscriptionId <string>] [-Environment <cloud>]

# Interactive (requires Az.Accounts)
Connect-AzArm [-TenantIdInteractive <string>] [-SubscriptionId <string>] [-Environment <cloud>]
```

### HTTP verbs

All functions return a `PSCustomObject` with `StatusCode`, `Headers`, `Body`,
and `RawContent`.

| Function | Mandatory params | Notes |
|---|---|---|
| `Invoke-ArmGet` | `ResourcePath`, `ApiVersion` | Read-only; no body |
| `Invoke-ArmPost` | `ResourcePath`, `ApiVersion` | `Body` optional |
| `Invoke-ArmPut` | `ResourcePath`, `ApiVersion`, `Body` | Idempotent create/replace |
| `Invoke-ArmPatch` | `ResourcePath`, `ApiVersion`, `Body` | Partial update |
| `Invoke-ArmDelete` | `ResourcePath`, `ApiVersion` | No body |
| `Invoke-ArmRequest` | `Method`, `ResourcePath`, `ApiVersion` | Generic wrapper |

Common optional parameters on all verbs:

| Parameter | Default | Description |
|---|---|---|
| `-WaitForCompletion` | `$false` | Poll LRO until terminal state |
| `-LroTimeoutSec` | `7200` | Max poll time |
| `-MaxRetries` | `3` | Retry count for transient errors |
| `-QueryParams` | `@{}` | Extra query-string parameters |
| `-AdditionalHeaders` | `@{}` | Extra request headers |

### Long-running operations

```powershell
# Automatic (preferred) – pass -WaitForCompletion to any mutating verb
$vm = Invoke-ArmPut -ResourcePath $vmPath -ApiVersion $api -Body $vmDef -WaitForCompletion

# Manual – poll a response you already have
$result = Watch-ArmOperation -InitialResponse $resp -GetToken { Get-AzArmToken }
```

### Logging

```powershell
Set-ArmLogLevel -Level DEBUG          # DEBUG | INFO | WARN | ERROR
Set-ArmLogFile  -Path .\arm.log       # write to file as well
Set-ArmLogFile  -Disable              # stop file logging
Write-ArmLog    -Level INFO -Message 'Custom message' -Data @{ key = 'value' }
```

---

## Integrity verification

AzArmClient-PS ships with a SHA-256 manifest (`modules.sha256`) that lists
every `.psm1` file hash.  The main script verifies these hashes before any
module is imported, preventing tampered or corrupted modules from running.

```powershell
# Regenerate the manifest after modifying a module
.\Build-AzArmClient.ps1 -SkipModuleDownload -CreateZip:$false

# Skip the check (not recommended in production)
. .\AzArmClient.ps1 -SkipIntegrityCheck
```

---

## Build script

`Build-AzArmClient.ps1` is for maintainers and CI pipelines:

```powershell
# Full build: download pinned Az.Accounts, regenerate manifest, create zip
.\Build-AzArmClient.ps1

# Regenerate manifest only
.\Build-AzArmClient.ps1 -SkipModuleDownload -CreateZip:$false

# Custom output locations
.\Build-AzArmClient.ps1 -OutputDir C:\Releases -ModuleCacheDir C:\AzCache
```

### Pinned dependencies

| Module | Version | Purpose |
|---|---|---|
| `Az.Accounts` | 2.15.1 | Interactive auth / `Get-AzAccessToken` |

To upgrade: edit `$script:PinnedModules` in `Build-AzArmClient.ps1` and re-run.

---

## Security notes

* **Tokens are never logged.**  `Get-AzArmToken` returns the raw token but
  `Invoke-ArmRequest` only injects it into the `Authorization` header – it is
  not passed to `Write-ArmLog`.
* **Client secrets are stored as `SecureString`** and converted to plain text
  only in the isolated `_GetTokenClientSecret` helper at the moment the token
  request is made.
* **Certificate private keys** are used only for JWT signing in
  `_GetTokenClientCert`; the key material is never serialised or stored.
* The integrity manifest should be committed to source control and treated as
  part of the release artefact so consumers can detect supply-chain tampering.

---

## Repository layout

```
AzArmClient-PS/
├── AzArmClient.ps1        # Main entry-point (dot-source to use)
├── Build-AzArmClient.ps1  # Maintainer build / bundle script
├── modules.sha256         # SHA-256 manifest (generated by build)
├── Modules/
│   ├── Auth.psm1          # Authentication helpers
│   ├── ArmRequests.psm1   # HTTP GET/POST/PUT/PATCH/DELETE
│   ├── LongRunning.psm1   # LRO polling
│   ├── Logging.psm1       # Structured logging
│   └── Integrity.psm1     # Hash verification
├── PSModuleCache/         # Bundled Az modules (generated by build, not committed)
└── dist/                  # Distribution zip (generated by build, not committed)
```

---

## Requirements

* PowerShell 5.1 or PowerShell 7+
* `Az.Accounts` 2.15.1 (required only for **Interactive** authentication;
  bundled by the build script or install manually:
  `Install-Module Az.Accounts -RequiredVersion 2.15.1`)

## License

MIT – see [LICENSE](LICENSE).

