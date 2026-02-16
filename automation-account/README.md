# Automation Account azd solution

Deploys a production-style Maester automation solution on Azure with:

- Azure Automation (PowerShell 7.4 runtime)
- Managed identity + Graph permissions
- Storage-backed report history (`archive`) and latest pointer (`latest/latest.html`)
- Optional App Service + Easy Auth portal in WebApp mode

## Quickstart (recommended)

After `azd init -t <your-template-id>` and `cd automation-account`, run one command:

`./scripts/Start-Setup.ps1 -IncludeWebApp -SecurityGroupObjectId <groupObjectId>`

For quick mode (no web app), run with no mode flags:

`./scripts/Start-Setup.ps1`

What this does:

- signs in with Azure CLI if needed
- lets you choose a subscription if not provided
- initializes azd environment values
- runs `azd provision --no-prompt --no-state`
- executes pre/post hooks for setup + validation

## Modes

- **Quick**: Automation + Storage
- **WebApp**: Quick + Web App (Entra auth restricted by security group)

Defaults:

- `PERMISSION_PROFILE=Extended`
- `WEB_APP_SKU=F1`
- resource group pattern: `rg-<environment>-<location>` (override with `-ResourceGroupName`)

## Operations

- Full deployment verification (optional):
  `./scripts/Test-AzdDeployment.ps1 -EnvironmentName <env> -SubscriptionId <subId> -TenantId <tenantId> -IncludeWebApp $true -SecurityGroupObjectId <groupObjectId>`
- Remove environment + Azure resources:
  `./scripts/Remove-AzdEnvironment.ps1 -EnvironmentName <env>`
- Remove Azure resources but keep local azd env:
  `./scripts/Remove-AzdEnvironment.ps1 -EnvironmentName <env> -KeepEnvironment`

## Script map

- User entry point: `scripts/Start-Setup.ps1`
- Environment setup: `scripts/Initialize-AzdEnvironment.ps1`
- azd hooks: `scripts/Run-AzdPreProvision.ps1`, `scripts/Run-AzdPostProvision.ps1`
- Internal setup/validation: `scripts/Setup-PostDeploy.ps1`, `scripts/Invoke-RunbookValidation.ps1`
- Automation runbook payload script (published into Automation): `scripts/Invoke-MaesterAutomationRunbook.ps1`
- Optional utilities: `scripts/Test-AzdDeployment.ps1`, `scripts/Remove-AzdEnvironment.ps1`

## Runtime behavior

- Weekly schedule (Sunday UTC)
- Outputs:
  - `archive/maester-report-<timestamp>.html.gz`
  - `latest/latest.html`
- In WebApp mode, latest report is published to Web App `index.html`
- Entra auth via app registration + admin consent are configured automatically
- Signed-in deployment user is granted `Storage Blob Data Reader` on the solution storage account
- Blob soft delete is enabled for 1 day, with blob versioning disabled
- Archive uploads are gzip compressed and written directly to Cool tier
- Lifecycle policy moves `archive` blobs to Cold tier after 180 days and deletes after 365 days
- Key resources are tagged and protected with `CanNotDelete` locks by default
- Automation identity uses `Website Contributor` (least privilege for web content publish) on the optional Web App

## Security recommendations

This solution is reasonably secure, but there are additional controls you may choose to implement based on your organization requirements:

- **Storage private networking:** Use Private Endpoint + storage firewall rules to restrict data plane access to approved networks only.
- **Web App private networking:** Use App Service Private Endpoint and access restrictions if your organization requires private-only ingress.
- **Centralized logging:** Send resource logs/metrics to a central Log Analytics workspace (or SIEM) for audit and incident response.
- **Conditional Access:** Apply tenant-wide baseline Conditional Access policies for user sign-in controls (MFA, device/risk posture).

## Reference docs

- Azure Developer CLI overview: https://learn.microsoft.com/azure/developer/azure-developer-cli/
- azd templates: https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-templates
- azd hooks/extensibility: https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-extensibility
- Manage azd environment variables: https://learn.microsoft.com/azure/developer/azure-developer-cli/manage-environment-variables
- App Service custom domain: https://learn.microsoft.com/azure/app-service/app-service-web-tutorial-custom-domain
