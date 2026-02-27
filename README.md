# azd-maester

Production-style `azd` templates for running Maester on Azure with managed identity and minimal operator steps.

## Solutions

- [automation-account](automation-account\README.md): End-to-end scheduled Maester solution (recommended baseline)
- [container-app-job](container-app-job\README.md): Scheduled Maester execution using Azure Container Apps Jobs
- [function-app](function-app\README.md): Maester execution using a PowerShell Azure Function App
- [azure-devops](azure-devops\README.md): End-to-end Azure DevOps pipeline automation with workload identity federation

## Recommended starting point

Use `automation-account` first. It has the most complete one-command experience and serves as the reference pattern for the other solutions.

## Quickstart by solution

After `azd init -t <your-template-id>`, choose a folder:

- ### [automation-account](automation-account\README.md)
  - `cd automation-account`
  - `azd up`
- ### [container-app-job](container-app-job\README.md)
  - `cd container-app-job`
  - `azd up`
- ### [function-app](function-app\README.md)
  - `cd function-app`
  - `azd up`
- ### [azure-devops](azure-devops\README.md)
  - `cd azure-devops`
  - `azd up`

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
- Managed identity by default
- PowerShell setup scripts use:
  - `Az.Accounts` + `Invoke-AzRestMethod` for Azure control plane
  - `Microsoft.Graph.Authentication` + `Invoke-MgGraphRequest` for Graph

## Reference docs

- Azure Developer CLI: https://learn.microsoft.com/azure/developer/azure-developer-cli/
- azd templates: https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-templates
- azd hooks/extensibility: https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-extensibility
