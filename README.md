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
