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
- Runtime hash validation is enabled by default.
- Signature validation is available through `-EnforceSignatureValidation`.
- Tokens and authorization headers are redacted from log output.
- `Logs\` and `Output\` are runtime folders and are not intended for source control.

## Module Resolution Behavior

Default behavior is deterministic:

- Use a bundled module when no newer valid installed version is available.
- Prefer a newer installed version when it is valid and importable.
- Use `-PreferBundledModules` to force bundled content.
- Use `-PreferInstalledModules` to make the installed-module preference explicit.

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
