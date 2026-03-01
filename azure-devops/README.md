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

`azd up`

During interactive `azd up`, the preprovision wizard prompts for:

- Include Web App / Exchange / Teams / Azure
- Security group object ID (required when Web App is enabled)
- Azure RBAC scopes (when Azure is enabled)
- Azure DevOps organization/project (required)
- Optional mail recipient

For non-interactive runs (`azd up --no-prompt`), if `AZURE_RESOURCE_GROUP` is set, `preup` creates it automatically when missing.

## What setup does

- Resolves azd environment values through the preprovision wizard and provisions Azure infra.
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

## Permission lifecycle

- Toggling an option from `Yes` to `No` in a later `azd up` run is additive only and does **not** revoke prior assignments.
- Revocation/best-effort cleanup runs on `azd down` (predown hook).

## Operations

- Provision/update:
  - `azd up -e <env>`
- Remove environment + Azure resources + Azure DevOps artifacts (includes predown cleanup):
  - `azd down -e <env> --force --purge`
- Optionally remove local azd env files:
  - `azd env remove <env> --force`

### Teardown behavior

`azd down` runs `scripts/Run-AzdPreDown.ps1`, which performs best-effort cleanup of:

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

- azd hooks: `scripts/Run-AzdPreUp.ps1`, `scripts/Run-AzdPreProvision.ps1`, `scripts/Run-AzdPostProvision.ps1`, `scripts/Run-AzdPreDown.ps1`
- Core provisioning: `scripts/Setup-PostDeploy.ps1`
- Pipeline runtime script (committed to Azure Repos): `scripts/Invoke-MaesterAzureDevOpsRun.ps1`
- Pipeline validation: `scripts/Invoke-PipelineValidation.ps1`

## Reference docs

- Maester Azure DevOps guide: https://maester.dev/docs/monitoring/azure-devops
- Azure DevOps pipeline schedule syntax: https://learn.microsoft.com/azure/devops/pipelines/process/scheduled-triggers
- Azure Developer CLI hooks: https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-extensibility
