# Azure DevOps azd solution

Deploys a production-style Maester monitoring solution using Azure DevOps Pipelines with:

- Azure DevOps Azure Repos Git repository + YAML pipeline
- Azure DevOps Azure Resource Manager service connection using workload identity federation (no secrets/certificates)
- Entra workload identity app + federated credential automation
- Managed identity style permissions (Graph app roles + optional Exchange/Teams/Azure)
- Storage-backed report history (`archive`) and latest pointer (`latest/latest.html`)
- Optional App Service + Easy Auth portal in WebApp mode

## Quickstart (existing Azure DevOps project)

After `azd init -t <your-template-id>` and `cd azure-devops`, run:

`./scripts/Start-Setup.ps1 -AdoOrganization <orgName> -AdoProject <projectName>`

Example with optional web app and advanced scopes:

`./scripts/Start-Setup.ps1 -AdoOrganization contoso -AdoProject maester -IncludeWebApp -SecurityGroupObjectId <groupObjectId> -IncludeExchange -IncludeTeams -IncludeAzure`

## What setup does

- Initializes azd environment values and provisions Azure infra.
- Creates or reuses Azure Repos repository (default enabled).
- Creates or reuses Azure DevOps service connection with workload identity federation (`CreationMode=Manual`).
- Creates or reuses Entra app/service principal and federated credential.
- Finalizes service connection with the federated app identity.
- Grants Graph app roles required by Maester (`Minimal` or `Extended` profile).
- Optionally grants:
  - Exchange `Exchange.ManageAsApp` + Exchange RBAC `View-Only Configuration`
  - Entra `Teams Reader`
  - Azure RBAC `Reader` at selected scopes
- Renders and pushes pipeline files to Azure Repos.
- Creates or reuses pipeline and validates first run (default enabled).

## Supported parameters

- Common include flags:
  - `-IncludeExchange`
  - `-IncludeTeams`
  - `-IncludeAzure`
  - `-IncludeWebApp`
- Web app security restriction:
  - `-SecurityGroupObjectId` (required when `-IncludeWebApp`)
  - `-SecurityGroupDisplayName` (optional resolver)
- Azure DevOps settings:
  - `-AdoOrganization` (required)
  - `-AdoProject` (required)
  - `-AdoRepositoryName` (default: `maester-<env>`)
  - `-AdoPipelineName` (default: `maester-weekly`)
  - `-AdoServiceConnectionName` (default: `sc-maester-<env>`)
  - `-PipelineYamlPath` (default: `/azure-pipelines.yml`)
  - `-DefaultBranch` (default: `main`)
  - `-ScheduleCron` (default: `0 0 * * 0`)
  - `-CreateRepositoryIfMissing` (default: `true`)
  - `-PushPipelineFiles` (default: `true`)
  - `-ValidatePipelineRun` (default: `true`)
- Additional standard options:
  - `-EnvironmentName`, `-SubscriptionId`, `-Location`, `-ResourceGroupName`
  - `-PermissionProfile` (`Minimal` or `Extended`)
  - `-AzureScopes`
  - `-MailRecipient`

## Operations

- Setup (recommended entry point):
  - `./scripts/Start-Setup.ps1 ...`
- Remove environment + Azure resources + Azure DevOps artifacts:
  - `./scripts/Remove-AzdEnvironment.ps1 -EnvironmentName <env>`
- Remove Azure resources but keep local azd env files:
  - `./scripts/Remove-AzdEnvironment.ps1 -EnvironmentName <env> -KeepEnvironment`

### Teardown behavior

`Remove-AzdEnvironment.ps1` performs best-effort cleanup of:

- Azure DevOps pipeline
- Azure DevOps service connection
- Azure DevOps repository
- Entra workload identity app registration
- Easy Auth Entra app (if created)
- Tracked Teams/Exchange/Azure role assignments created during setup

## Notes

- This solution intentionally avoids secrets and certificates.
- If automatic repository push fails, setup writes manual files to `outputs/<env>-pipeline-files`.
- Setup summary is written to `outputs/<env>-setup-summary.md`.

## Script map

- User entry point: `scripts/Start-Setup.ps1`
- Environment setup: `scripts/Initialize-AzdEnvironment.ps1`
- azd hooks: `scripts/Run-AzdPreProvision.ps1`, `scripts/Run-AzdPostProvision.ps1`
- Core provisioning: `scripts/Setup-PostDeploy.ps1`
- Pipeline runtime script (committed to Azure Repos): `scripts/Invoke-MaesterAzureDevOpsRun.ps1`
- Pipeline validation: `scripts/Invoke-PipelineValidation.ps1`
- Teardown: `scripts/Remove-AzdEnvironment.ps1`
- Quick smoke helper (no web app): `run-test-noweb.ps1`

## Reference docs

- Maester Azure DevOps guide: `/.resources/maester/website/docs/monitoring/azure-devops.md`
- Maester Azure DevOps WebApp+Bicep guide: `/.resources/maester/website/docs/monitoring/azure-devops-web-app-bicep.md`
- Azure DevOps pipeline schedule syntax: https://learn.microsoft.com/azure/devops/pipelines/process/scheduled-triggers
- Azure Developer CLI hooks: https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-extensibility
