# azd-maester

Production-style `azd` templates for running Maester on Azure with managed identity and minimal operator steps.

## Solutions

- `automation-account`: End-to-end scheduled Maester solution (recommended baseline)
- `container-app-job`: Scheduled Maester execution using Azure Container Apps Jobs
- `function-app`: Maester execution using a PowerShell Azure Function App
- `web-app`: Web hosting for Maester HTML reports
- `azure-devops`: CI/CD integration guidance for all solution folders

## Recommended starting point

Use `automation-account` first. It has the most complete one-command experience and serves as the reference pattern for the other solutions.

## Quickstart by solution

After `azd init -t <your-template-id>`, choose a folder:

- `automation-account`
  - `cd automation-account`
  - `./scripts/Start-Setup.ps1 -IncludeWebApp -SecurityGroupObjectId <groupObjectId>`
  - Optional: add `-IncludeExchange`, `-IncludeTeams`, and/or `-IncludeAzure` for additional data collection.
- `container-app-job`
  - `cd container-app-job`
  - `azd provision`
- `function-app`
  - `cd function-app`
  - `azd provision`
- `web-app`
  - `cd web-app`
  - `azd provision`
  - `./scripts/Publish-MaesterReport.ps1 -ReportPath <path-to-report.html> -SubscriptionId <subId> -ResourceGroupName <rgName> -WebAppName <webAppName>`
- `azure-devops`
  - `cd <solution-folder>`
  - `azd pipeline config --provider azdo`

For deeper details, use the README in each solution folder.

## Shared conventions

- `azd`-first provisioning and hooks
- Managed identity by default
- PowerShell setup scripts use:
  - `Az.Accounts` + `Invoke-AzRestMethod` for Azure control plane
  - `Microsoft.Graph.Authentication` + `Invoke-MgGraphRequest` for Graph

## Reference docs

- Azure Developer CLI: https://learn.microsoft.com/azure/developer/azure-developer-cli/
- azd templates: https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-templates
- azd hooks/extensibility: https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-extensibility
