<p align="center">
  <img src="assets/armclient-ps-logo.png" alt="ArmClient-PS logo" width="180" height="180">
</p>

# ArmClient-PS

ArmClient-PS is a single-script Azure Resource Manager support tool designed for redistribution.
It recreates the core ARMClient workflow by using `Invoke-AzRestMethod` and a locally bundled `Modules` folder instead of requiring runtime installation from the PowerShell Gallery.

## Goals

- Ship as a zip-friendly support package.
- Prefer secure, process-scoped authentication behavior.
- Validate packaged files before use.
- Support ARM GET, POST, PUT, PATCH, and DELETE operations.
- Allow newer valid locally installed modules when they are safer or more current than the bundled version.

## Package Layout

```text
.
├── ArmClient-PS.ps1
├── ArmClient-PS.Gui.ps1
├── Build-BundledModules.ps1
├── Modules\
├── Manifest\
│   ├── Files.sha256.json
│   └── Versions.json
├── Logs\
└── Output\
```

## Runtime Usage

Show context:

```powershell
.\ArmClient-PS.ps1 -ShowContext
```

Run a GET request:

```powershell
.\ArmClient-PS.ps1 `
  -Method GET `
  -RelativePath "/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>" `
  -ApiVersion "2021-04-01"
```

Run a POST request (equivalent to `armclient post /subscriptions/`):

```powershell
.\ArmClient-PS.ps1 `
  -Method POST `
  -RelativePath "/subscriptions" `
  -ApiVersion "2022-12-01"
```

Run a POST request with a JSON body:

```powershell
.\ArmClient-PS.ps1 `
  -Method POST `
  -RelativePath "/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/<providerNamespace>/<resourceType>/<resourceName>/<action>" `
  -ApiVersion "2021-04-01" `
  -Body '{"key":"value"}'
```

Run a POST request with a JSON body file:

```powershell
.\ArmClient-PS.ps1 `
  -Method POST `
  -RelativePath "/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/<providerNamespace>/<resourceType>/<resourceName>/<action>" `
  -ApiVersion "2021-04-01" `
  -BodyFile "request-body.json"
```

Save a response to disk:

```powershell
.\ArmClient-PS.ps1 `
  -Method GET `
  -RelativePath "/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>" `
  -ApiVersion "2021-04-01" `
  -OutputFile "resource-group.json"
```

Inspect resolved module versions:

```powershell
.\ArmClient-PS.ps1 -ShowResolvedModuleVersions
```

Run the built-in package self-test:

```powershell
.\ArmClient-PS.ps1 -SelfTest
```

## Graphical Interface

`ArmClient-PS.Gui.ps1` is an optional WPF front end for the same tool. It calls `ArmClient-PS.ps1` for every
request, so behavior, logging, redaction, and validation are identical to the command line.

```powershell
.\ArmClient-PS.Gui.ps1
```

It runs on Windows PowerShell 5.1 and PowerShell 7.x. A single-threaded apartment is required; the script
relaunches itself in STA when it is started from an MTA host, so no special invocation is needed.

What it provides:

- **Operation catalog.** Verified presets grouped by service, plus every ARM operation your subscription
  exposes once you select **Discover all**. Search filters by name, alias, category, or description.
- **Only what I have deployed.** Hides resource types that do not exist in the current subscription.
- **Guided parameters.** Lookups that can be resolved are offered as lists. Choosing a subscription fills the
  resource group list, and choosing a resource group fills the resource list.
- **Request modes.** Operation preset, relative ARM path, or absolute HTTPS URI.
- **Parameter defaults.** Store a subscription, resource group, or any other value once and have it pre-fill
  every operation. Saved defaults are encrypted for the current Windows account and validated against the
  signed-in tenant.
- **Tenant switching.** Switch directory without restarting. State that belonged to the previous tenant is
  discarded rather than carried over.
- **Documentation links.** Per-operation deep links to the Microsoft Learn REST reference, resolved at click
  time and restricted to `learn.microsoft.com`.
- **Response handling.** Status code, elapsed time, response headers, and a session activity log. Secrets are
  redacted until **Reveal raw** is used.
- **Copy as CLI.** Emits the equivalent `ArmClient-PS.ps1` command line for the request on screen.
- **Getting started guide.** Shown on launch and reachable at any time from **Guide** in the toolbar.

Paths for discovered operations are derived from ARM provider metadata. Where Microsoft publishes an exact URL
for an operation the tool uses it and labels the request **DOCUMENTED PATH**; everything else is labelled
**INFERRED PATH**, and a write or delete against an inferred path says so in its confirmation prompt.

The GUI is a client only. It adds no new network destinations beyond Resource Manager for the selected cloud
and `learn.microsoft.com` for documentation links.

## Azure Communication Services – Domain Verification

ArmClient-PS ships built-in operation presets for Azure Communication Services (ACS) email domain verification.
Accepted verification types are `Domain`, `SPF`, `DKIM`, `DKIM2`, and `DMARC`.

### Initiate verification (using Operation preset)

**SPF**

```powershell
.\ArmClient-PS.ps1 `
  -Operation "AcsEmailDomainInitiateVerification" `
  -OperationParameters @{
      subscriptionId    = "<subscription-id>"
      resourceGroupName = "<resourceGroupName>"
      emailServiceName  = "<emailServiceName>"
      domainName        = "<domainName>"
      verificationType  = "SPF"
  }
```

**DKIM**

```powershell
.\ArmClient-PS.ps1 `
  -Operation "AcsEmailDomainInitiateVerification" `
  -OperationParameters @{
      subscriptionId    = "<subscription-id>"
      resourceGroupName = "<resourceGroupName>"
      emailServiceName  = "<emailServiceName>"
      domainName        = "<domainName>"
      verificationType  = "DKIM"
  }
```

**DKIM2**

```powershell
.\ArmClient-PS.ps1 `
  -Operation "AcsEmailDomainInitiateVerification" `
  -OperationParameters @{
      subscriptionId    = "<subscription-id>"
      resourceGroupName = "<resourceGroupName>"
      emailServiceName  = "<emailServiceName>"
      domainName        = "<domainName>"
      verificationType  = "DKIM2"
  }
```

**DMARC**

```powershell
.\ArmClient-PS.ps1 `
  -Operation "AcsEmailDomainInitiateVerification" `
  -OperationParameters @{
      subscriptionId    = "<subscription-id>"
      resourceGroupName = "<resourceGroupName>"
      emailServiceName  = "<emailServiceName>"
      domainName        = "<domainName>"
      verificationType  = "DMARC"
  }
```

### Cancel verification (using Operation preset)

```powershell
.\ArmClient-PS.ps1 `
  -Operation "AcsEmailDomainCancelVerification" `
  -OperationParameters @{
      subscriptionId    = "<subscription-id>"
      resourceGroupName = "<resourceGroupName>"
      emailServiceName  = "<emailServiceName>"
      domainName        = "<domainName>"
      verificationType  = "DKIM2"   # replace with SPF, DKIM, DKIM2, DMARC, or Domain
  }
```

### Initiate verification using raw RelativePath (equivalent to `armclient post /subscriptions/...`)

```powershell
.\ArmClient-PS.ps1 `
  -Method POST `
  -RelativePath "/subscriptions/<subscription-id>/resourceGroups/<resourceGroupName>/providers/Microsoft.Communication/emailServices/<emailServiceName>/domains/<domainName>/initiateVerification" `
  -ApiVersion "2023-03-31" `
  -Body '{"verificationType":"DKIM2"}'
```

Replace `DKIM2` with `SPF`, `DKIM`, `DMARC`, or `Domain` as needed.

## Maintainer Build Workflow

Rebuild bundled modules and manifests:

```powershell
.\Build-BundledModules.ps1 -ToolVersion 1.0.0 -Clean -Force
```

Optional signing flow:

```powershell
.\Build-BundledModules.ps1 `
  -ToolVersion 1.0.0 `
  -Clean `
  -Force `
  -CodeSigningThumbprint "<thumbprint>"
```

## Security Notes

- Runtime execution disables Az context autosave for the current process.
- Runtime hash validation is enabled by default. Every packaged file under `Modules\` must be listed in
  `Manifest\Files.sha256.json`; an added file that is not in the manifest fails the run, because Az modules
  dot-source everything in their `StartupScripts` and `PostImportScripts` folders.
- `ArmClient-PS.Gui.ps1` is hash validated whenever it is present beside the script. Deleting it is supported
  and leaves the command line fully functional; modifying it fails the run.
- Manifest paths must stay inside the package folder. Rooted paths and `..` traversal are rejected.
- Signature validation is available through `-EnforceSignatureValidation`.
- Tokens and authorization headers are redacted from log output, including bare JWTs, SAS `sig` values, and PEM private keys.
- Long-running operation polling targets are taken from response headers, so they are restricted to the Resource
  Manager host for the selected environment over HTTPS. This keeps an access token from being sent elsewhere.
- When `-Headers` is supplied the request is issued with an explicit bearer token and redirects are not followed.
- `Logs\` and `Output\` are runtime folders and are not intended for source control.

> The hash manifest detects modification of an already-trusted package. It is not a substitute for authenticating
> the download itself, because an attacker who can rewrite the package can also rewrite the manifest. Verify the
> release archive through a signed or independently published checksum before first use.

## Module Resolution Behavior

Default behavior is deterministic:

- Use a bundled module when no newer valid installed version is available.
- Prefer a newer installed version when it is valid and importable.
- Use `-PreferBundledModules` to force bundled content, falling back to an installed copy only if the bundled import fails.
- Use `-PreferInstalledModules` to force a locally installed copy even when the bundled version is newer, falling back to the bundled copy only if the installed import fails.

## Long-Running Operations

ARM operations that return `201`/`202` are polled to completion by default. Polling honors a service-supplied
`Retry-After` header, and otherwise backs off from the starting interval to a 30 second ceiling.

```powershell
# Return the initial 202 immediately instead of polling.
.\ArmClient-PS.ps1 -Operation "AcsEmailDomainInitiateVerification" -OperationParameters @{ ... } -NoWait

# Poll every 15 seconds and allow up to 4 hours.
.\ArmClient-PS.ps1 -Method PUT -RelativePath "/subscriptions/<id>/resourceGroups/<rg>" -ApiVersion "2021-04-01" `
  -BodyFile "rg.json" -PollIntervalSeconds 15 -LongRunningTimeoutSeconds 14400
```

Use `-LongRunningTimeoutSeconds 0` to wait indefinitely. Throttled (`429`) and transient responses are retried
automatically; `5xx` responses are only retried for idempotent methods so a `POST` action is never replayed.

## Distribution Guidance

Before distributing the package:

1. Run `Build-BundledModules.ps1` on a maintainer machine.
2. Confirm `Manifest\Files.sha256.json` and `Manifest\Versions.json` were regenerated.
3. Run `ArmClient-PS.ps1 -SelfTest` from the packaged folder.
4. Zip the entire folder structure without removing the `Modules` or `Manifest` folders.

## Release Automation

The `Release Package` GitHub Actions workflow creates `AzArmClient-PS.zip` from an exact repository commit. The archive contains the runtime scripts, license, README, manifests, and bundled modules under one `AzArmClient-PS` folder. Before publishing, the workflow extracts the archive and runs its built-in self-test.

The workflow then:

1. Creates or updates the `v<version>` GitHub release and its `AzArmClient-PS.zip` asset.
2. Formats the supplied additions under `# Change Log` and `## Additions`.
3. Adds a version-specific download-count badge to the release notes.
4. Optionally uploads the same archive to SFTP as `AzArmClient-PS.zip`.

Run it manually from **Actions > Release Package > Run workflow**. Leave the version blank to read it from the `Version` setting in `ArmClient-PS.ps1`, or supply a version with or without the leading `v` to override the release tag, title, and notes. An override does not rewrite the committed package files. Enter release additions one item per line. Set **Upload SFTP** to `false` until the SFTP secrets are configured. A version tag cannot be reused for a different commit, so bump the tool version before publishing another release. Automated bundled-module updates invoke the same workflow after their rebuilt commit passes package validation and is pushed.

### SFTP Configuration

SFTP publishing uses an OpenSSH private key and strict host-key checking. Add these under **Settings > Secrets and variables > Actions**:

| Type | Name | Value |
| --- | --- | --- |
| Variable | `SFTP_ENABLED` | `true` to upload automatic module-update releases; otherwise `false` or unset |
| Secret | `SFTP_HOST` | SFTP server host name |
| Secret | `SFTP_PORT` | Optional port; defaults to `22` |
| Secret | `SFTP_USERNAME` | Restricted SFTP deployment account |
| Secret | `SFTP_PRIVATE_KEY` | Unencrypted private key for unattended key authentication |
| Secret | `SFTP_KNOWN_HOSTS` | Verified OpenSSH `known_hosts` entry for the server and port |
| Secret | `SFTP_REMOTE_DIRECTORY` | Optional existing remote directory; blank uploads to the account's SFTP home |

Install the matching public key on a restricted SFTP account with write access only to the release directory. Obtain the server's `known_hosts` entry with `ssh-keyscan`, but verify its fingerprint with the server administrator before saving it as a secret. Never commit the private key to the repository.
