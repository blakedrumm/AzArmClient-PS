# Changelog

All notable changes to ArmClient-PS are recorded here. This project follows
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## 1.1.0

### Added

- **`ArmClient-PS.Gui.ps1`, an optional WPF interface for the tool.** It dispatches every request through
  `ArmClient-PS.ps1`, so logging, redaction, host restrictions, and package validation are unchanged. Runs on
  Windows PowerShell 5.1 and PowerShell 7.x, and relaunches itself in STA when started from an MTA host.
  - Operation catalog combining verified presets with live discovery of every ARM operation the signed-in
    subscription exposes, searchable by name, alias, category, or description.
  - "Only what I have deployed" filter that hides resource types absent from the current subscription.
  - Guided parameter entry with chained lookups, so choosing a subscription fills the resource group list and
    choosing a resource group fills the resource list.
  - Parameter defaults stored per Windows account with DPAPI encryption, validated against the signed-in
    tenant so a stale subscription is flagged rather than used silently.
  - Tenant switching that discards catalog, response, and lookup state belonging to the previous tenant.
  - Per-operation documentation deep links to the Microsoft Learn REST reference, resolved at click time and
    restricted to `learn.microsoft.com`.
  - Response pane with status code, elapsed time, response headers, and a session activity log. Secrets stay
    redacted until "Reveal raw" is used.
  - "Copy as CLI" to emit the equivalent `ArmClient-PS.ps1` command line for the request on screen.
  - Getting started guide shown on launch and reachable from "Guide" in the toolbar.
  - Light and dark themes.
- Documented route table for the Resource Manager built-in types that are addressed off the root rather than
  through `/providers/{namespace}/`, covering `subscriptions`, `tenants`, `providers`, `resourcegroups`,
  `resources`, `locations`, `operationresults`, `tagNames`, and `tagValues`.
- Route provenance on discovered operations. A request built from a published Microsoft URL is labelled
  DOCUMENTED PATH; anything derived from RBAC metadata is labelled INFERRED PATH, and a write or delete
  against an inferred path states that in its confirmation prompt.
- Example values for the parameters Resource Manager's own URI grammar defines, and documented example request
  bodies for the routes that publish one.
- `ArmClient-PS.Gui.ps1` is hash validated when present. Removing it is supported and leaves the command line
  fully functional; modifying it fails the run.

### Changed

- API version selection now treats `-beta`, `-alpha`, and `-rc` as pre-release alongside `-preview`, so a
  release candidate is no longer chosen ahead of a newer stable version.
- The context banner shows the directory name followed by the tenant id, matching how the subscription is
  already displayed. The name is read once per sign-in and falls back to the raw tenant id when the account
  cannot list directories.
- The release archive and the packaged file inventory now include `ArmClient-PS.Gui.ps1`.

### Fixed

- Discovered operations for Resource Manager root built-in types produced unreachable URLs and returned HTTP
  404. `Microsoft.Resources/subscriptions/read` built
  `/providers/Microsoft.Resources/subscriptions` instead of `/subscriptions`.
- Scope confidence on a discovered operation was presented as though it covered the whole path. It describes
  the scope only, and now says so.
- The context banner overran the package integrity label instead of ellipsing, because the text sat inside a
  horizontal `StackPanel` that measures its children with infinite width. Long values are now trimmed with the
  full text available on hover.

## 1.0.7

- Refreshed bundled modules and hardened the validation workflows.

## 1.0.6

- Updated bundled Az.Accounts from 5.5.1 to 5.5.2.
- Added release automation and release note generation.

## 1.0.5

- Updated bundled Az.Accounts from 5.5.0 to 5.5.1.
- Byte fidelity enforcement and long-running operation handling improvements.

Releases before 1.0.5 are listed on the
[GitHub releases page](https://github.com/blakedrumm/AzArmClient-PS/releases).
