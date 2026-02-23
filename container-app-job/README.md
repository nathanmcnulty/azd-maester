# Container App Job azd solution

Deploys a production-style Maester automation solution on Azure with:

- Azure Container App Job (PowerShell 7.4 Mariner container)
- Managed identity + Graph permissions
- Runner script mounted via Azure Files volume
- Storage-backed report history (`archive`) and latest pointer (`latest/latest.html`)
- Optional Azure Container Registry with pre-built image for faster startup
- Optional App Service + Easy Auth portal in WebApp mode

## Quickstart (recommended)

After `azd init -t <your-template-id>` and `cd container-app-job`, run one command:

`./scripts/Start-Setup.ps1 -IncludeWebApp -SecurityGroupObjectId <groupObjectId>`

For quick mode (no web app), run with no mode flags:

`./scripts/Start-Setup.ps1`

## Advanced options (optional)

You can optionally enable additional data collection/connectivity for Maester by enabling one or more `-Include*` switches during setup.

- `-IncludeACR`
  - Deploys an Azure Container Registry (Basic SKU).
  - Builds a custom container image with all PowerShell modules pre-installed for significantly faster job startup.
  - Grants the Container App Job managed identity the `AcrPull` role.
- `-IncludeExchange`
  - Ensures the `ExchangeOnlineManagement` module is available at runtime.
  - Grants the Container App Job managed identity the Exchange app permission required for app-only Exchange Online access.
  - Creates/links an Exchange service principal for the managed identity and assigns the Exchange RBAC role `View-Only Configuration` (best-effort).
- `-IncludeTeams`
  - Ensures the `MicrosoftTeams` module is available at runtime.
  - Assigns the Entra directory role `Teams Reader` to the Container App Job managed identity.
- `-IncludeAzure`
  - Grants Azure RBAC `Reader` to the Container App Job managed identity at one or more scopes.
  - Scopes can be management groups and/or subscriptions.

Examples:

- Enable ACR for faster startup:
  - `./scripts/Start-Setup.ps1 -IncludeACR`
- Enable Exchange + Teams:
  - `./scripts/Start-Setup.ps1 -IncludeExchange -IncludeTeams`
- Enable Azure and select scopes interactively:
  - `./scripts/Start-Setup.ps1 -IncludeAzure`
- Enable Azure with explicit scopes:
  - `./scripts/Start-Setup.ps1 -IncludeAzure -AzureScopes '/providers/Microsoft.Management/managementGroups/<mgName>','/subscriptions/<subId>'`
- Full options:
  - `./scripts/Start-Setup.ps1 -IncludeWebApp -IncludeACR -IncludeExchange -IncludeTeams -IncludeAzure -SecurityGroupObjectId <groupObjectId>`

### Permission behavior

- Advanced permission steps are performed using the privileges of the user running setup.
- If a step fails due to missing privileges, the scripts will:
  - Prompt you to **Stop** or **Skip** in interactive runs.
  - Default to **Skip + continue** in non-interactive runs (CI).

What this does:

- signs in with Azure CLI if needed
- lets you choose a subscription if not provided
- initializes azd environment values
- runs `azd provision --no-prompt --no-state`
- executes pre/post hooks for setup + validation

## Modes

- **Quick**: Container App Job + Storage
- **WebApp**: Quick + Web App (Entra auth restricted by security group)

Defaults:

- `PERMISSION_PROFILE=Extended`
- `WEB_APP_SKU=F1`
- resource group pattern: `rg-<environment>-<location>` (override with `-ResourceGroupName`)

## Operations

- Remove environment + Azure resources:
  `./scripts/Remove-AzdEnvironment.ps1 -EnvironmentName <env>`
- Remove Azure resources but keep local azd env:
  `./scripts/Remove-AzdEnvironment.ps1 -EnvironmentName <env> -KeepEnvironment`

### Cleanup details

`Remove-AzdEnvironment.ps1` performs best-effort cleanup for tenant/scope-level assignments created by advanced options before running `azd down`, including:

- Teams directory role assignments (`Teams Reader`) created by this environment
- Azure RBAC role assignments created by this environment (at selected scopes)
- Exchange Online permissions/assignments created by this environment (best-effort)

The generated setup summary in `outputs/<env>-setup-summary.md` includes tracked assignment IDs used for cleanup.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ Container App Environment                                        │
│   ┌────────────────────────────┐   ┌─────────────────────────┐   │
│   │ Container App Job          │   │ Azure Files Mount       │   │
│   │ (weekly schedule)          │──▶│ /mnt/scripts            │   │
│   │ pwsh -File ...ps1          │   │ Invoke-MaesterContainer │   │
│   │ MI: System-Assigned        │   │ Job.ps1                 │   │
│   └──────┬─────────────────────┘   └─────────────────────────┘   │
│          │                                                       │
└──────────┼───────────────────────────────────────────────────────┘
           │
    ┌──────┼──────────────────────────────────────────────┐
    │      ▼                                              │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
    │  │ Graph    │  │ Storage  │  │ Web App  │ optional  │
    │  │ + EXO    │  │ archive/ │  │ Easy Auth│           │
    │  │ + Teams  │  │ latest/  │  │ portal   │           │
    │  └──────────┘  └──────────┘  └──────────┘           │
    │                                                     │
    │  ┌──────────┐                                       │
    │  │ ACR      │ optional (pre-built image)            │
    │  └──────────┘                                       │
    └─────────────────────────────────────────────────────┘
```

## Script map

- User entry point: `scripts/Start-Setup.ps1`
- Environment setup: `scripts/Initialize-AzdEnvironment.ps1`
- azd hooks: `scripts/Run-AzdPreProvision.ps1`, `scripts/Run-AzdPostProvision.ps1`
- Internal setup/validation: `scripts/Setup-PostDeploy.ps1`, `scripts/Invoke-JobValidation.ps1`
- Container runner script (uploaded to Azure Files): `scripts/Invoke-MaesterContainerJob.ps1`
- ACR image build: `scripts/Build-MaesterImage.ps1`, `Dockerfile`
- Teardown: `scripts/Remove-AzdEnvironment.ps1`

## Runtime behavior

- Weekly schedule (Sunday midnight UTC). To run at a different time or frequency, edit the `cronExpression` in `infra/main.bicep` (e.g. `'30 6 * * 1'` for Monday 6:30 UTC), then re-run `azd provision`.
- Default image: `mcr.microsoft.com/powershell:lts-mariner-2.0` (modules installed at startup)
- With `-IncludeACR`: custom image with modules pre-installed (faster startup)
- Runner script is always mounted from Azure Files (never baked into image) for easy updates
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
- Container App Job identity uses `Website Contributor` (least privilege for web content publish) on the optional Web App
- Container resources: 1 vCPU, 2 GiB memory, 1-hour timeout, 1 retry

## Security recommendations

This solution is reasonably secure, but there are additional controls you may choose to implement based on your organization requirements:

- **Storage private networking:** Use Private Endpoint + storage firewall rules to restrict data plane access to approved networks only.
- **Container App Environment networking:** Deploy the environment into a custom VNet for network isolation.
- **Web App private networking:** Use App Service Private Endpoint and access restrictions if your organization requires private-only ingress.
- **Centralized logging:** Send resource logs/metrics to a central Log Analytics workspace (or SIEM) for audit and incident response.
- **Conditional Access:** Apply tenant-wide baseline Conditional Access policies for user sign-in controls (MFA, device/risk posture).

## Reference docs

- Azure Developer CLI overview: https://learn.microsoft.com/azure/developer/azure-developer-cli/
- azd templates: https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-templates
- azd hooks/extensibility: https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-extensibility
- Manage azd environment variables: https://learn.microsoft.com/azure/developer/azure-developer-cli/manage-environment-variables
- Azure Container Apps Jobs: https://learn.microsoft.com/azure/container-apps/jobs
- Azure Container Apps storage: https://learn.microsoft.com/azure/container-apps/storage-mounts
- App Service custom domain: https://learn.microsoft.com/azure/app-service/app-service-web-tutorial-custom-domain
