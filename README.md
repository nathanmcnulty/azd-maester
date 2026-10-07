# azd-maester

Production-style `azd` templates for running Maester on Azure with Managed Identities and minimal operator steps.

> [!IMPORTANT]
> This repository contains multiple deployable solutions. The repository root is an intentional catalog and guard entry point, not a deployable Maester environment: choose one solution subfolder before running `azd up`. A root-level `azd up` exits before provisioning and prints the correct folder-specific command.

## Migration status

The supported long-term sources are four standalone public templates. Use the
standalone template name shown below for a new deployment. The folders in this
repository remain available only for existing catalog checkouts during the
migration.

| Legacy folder in this repository | Canonical standalone host | Host backlog | New deployment source | Existing catalog checkout command |
| --- | --- | --- | --- | --- |
| `automation-account` | [`nathanmcnulty/azd-maester-azureautomation`](https://github.com/nathanmcnulty/azd-maester-azureautomation) | [`docs/backlog.json`](https://github.com/nathanmcnulty/azd-maester-azureautomation/blob/main/docs/backlog.json) | `azd init -t nathanmcnulty/azd-maester-azureautomation` | `cd automation-account` then `azd up` |
| `container-app-job` | [`nathanmcnulty/azd-maester-containerappjob`](https://github.com/nathanmcnulty/azd-maester-containerappjob) | [`docs/backlog.json`](https://github.com/nathanmcnulty/azd-maester-containerappjob/blob/main/docs/backlog.json) | `azd init -t nathanmcnulty/azd-maester-containerappjob` | `cd container-app-job` then `azd up` |
| `function-app` | [`nathanmcnulty/azd-maester-functionapp`](https://github.com/nathanmcnulty/azd-maester-functionapp) | [`docs/backlog.json`](https://github.com/nathanmcnulty/azd-maester-functionapp/blob/main/docs/backlog.json) | `azd init -t nathanmcnulty/azd-maester-functionapp` | `cd function-app` then `azd up` |
| `azure-devops` | [`nathanmcnulty/azd-maester-azuredevops`](https://github.com/nathanmcnulty/azd-maester-azuredevops) | [`docs/backlog.json`](https://github.com/nathanmcnulty/azd-maester-azuredevops/blob/main/docs/backlog.json) | `azd init -t nathanmcnulty/azd-maester-azuredevops` | `cd azure-devops` then `azd up` |

Each standalone repository uses `main` as its default branch and its README
names the corresponding `azd init -t` source. Each template pins the stable
Maester module `2.2.0` and vendors shared hook/permission behavior and the
optional report web app from
[`azd-reference`](https://github.com/nathanmcnulty/azd-reference), with exact
component revisions and hashes in `azd-components.lock.json`.

Route future host defects and implementation work to the corresponding
standalone repository and its `docs/backlog.json`. This catalog backlog tracks
only remaining catalog/migration work and defects in the retained legacy copy.
The Azure DevOps reports [#12](https://github.com/nathanmcnulty/azd-maester/issues/12),
[#13](https://github.com/nathanmcnulty/azd-maester/issues/13),
[#14](https://github.com/nathanmcnulty/azd-maester/issues/14), and
[#15](https://github.com/nathanmcnulty/azd-maester/issues/15) remain open here.
The standalone Azure DevOps [PR #18](https://github.com/nathanmcnulty/azd-maester-azuredevops/pull/18)
fixes only repository staging when `TEMP` is absent; it does not resolve or
close those broader reports.

This catalog is intentionally not archived. Removing or archiving the legacy
folders requires separate authorization plus verified source history and
migration evidence.

https://github.com/user-attachments/assets/c2781a8e-46f6-4be0-8bf2-27f3b6425748

## Solutions

- [automation-account](automation-account/README.md): End-to-end scheduled Maester solution (recommended)
- [container-app-job](container-app-job/README.md): Scheduled Maester execution using Azure Container Apps Jobs
- [function-app](function-app/README.md): Maester execution using a PowerShell Azure Function App
- [azure-devops](azure-devops/README.md): End-to-end Azure DevOps pipeline automation with workload identity federation

## Recommended starting point

For a new deployment, start with
[`nathanmcnulty/azd-maester-azureautomation`](https://github.com/nathanmcnulty/azd-maester-azureautomation).
It has the simplest setup and serves as the reference pattern for the other
standalone solutions.

## Quickstart by solution

For a new deployment, run the standalone `azd init -t` command from the mapping
table, then run `azd up` from the initialized template root.

For an existing checkout of this catalog repository, choose a retained solution
folder and run `azd up` there:

- ### [automation-account](automation-account/README.md)
  - `cd automation-account`
  - `azd up`
- ### [container-app-job](container-app-job/README.md)
  - `cd container-app-job`
  - `azd up`
- ### [function-app](function-app/README.md)
  - `cd function-app`
  - `azd up`
- ### [azure-devops](azure-devops/README.md)
  - `cd azure-devops`
  - `azd up`

The repository root has no deployable infrastructure. If you run `azd up` from
the root, the guard prints these folder-specific legacy commands and exits before
provisioning.

`azd up` runs a full interactive preprovision wizard for include flags and required values (for example security group and Azure DevOps org/project).

Non-interactive note (`--no-prompt`): if `AZURE_RESOURCE_GROUP` is set, `preup` creates it automatically when missing.

## Teardown

- Remove resources and run cleanup hooks:
  - `azd down --force --purge`
- Optionally remove local environment state:
  - `azd env remove <env> --force`

## Permission lifecycle

- Switching an include flag from `Yes` to `No` on a later `azd up` does not revoke previously granted permissions.
- Revocation/best-effort cleanup happens during `azd down` (predown hook), then resources are deleted.

## Shared conventions

- `azd`-first provisioning and hooks
- `preprovision` wizard on every interactive `azd up`
- `predown` cleanup before resource deletion
- Managed Identities by default, no secrets or certificates
- PowerShell setup scripts use:
  - Azure CLI access tokens + `Invoke-RestMethod` for Microsoft Graph API

## Reference docs

- Azure Developer CLI: https://learn.microsoft.com/azure/developer/azure-developer-cli/
- azd templates: https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-templates
- azd hooks/extensibility: https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-extensibility
