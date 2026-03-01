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

`azd up`

During interactive `azd up`, the preprovision wizard prompts for:

- Include Web App / Exchange / Teams / Azure / ACR
- Security group object ID (required when Web App is enabled)
- Azure RBAC scopes (when Azure is enabled)
- Optional mail recipient

For non-interactive runs (`azd up --no-prompt`), if `AZURE_RESOURCE_GROUP` is set, `preup` creates it automatically when missing.

## Advanced options (optional)

You can optionally enable additional data collection/connectivity for Maester by enabling one or more include options in the `azd up` wizard.

- `IncludeACR`
  - Deploys an Azure Container Registry (Basic SKU).
  - Builds a custom container image with all PowerShell modules pre-installed for significantly faster job startup.
  - Grants the Container App Job managed identity the `AcrPull` role.
- `IncludeExchange`
  - Ensures the `ExchangeOnlineManagement` module is available at runtime.
  - Grants the Container App Job managed identity the Exchange app permission required for app-only Exchange Online access.
  - Creates/links an Exchange service principal for the managed identity and assigns the Exchange RBAC role `View-Only Configuration` (best-effort).
- `IncludeTeams`
  - Ensures the `MicrosoftTeams` module is available at runtime.
  - Assigns the Entra directory role `Teams Reader` to the Container App Job managed identity.
- `IncludeAzure`
  - Grants Azure RBAC `Reader` to the Container App Job managed identity at one or more scopes.
  - Scopes can be management groups and/or subscriptions.

### Permission behavior

- Advanced permission steps are performed using the privileges of the user running setup.
- If a step fails due to missing privileges, the scripts will:
  - Prompt you to **Stop** or **Skip** in interactive runs.
  - Default to **Skip + continue** in non-interactive runs (CI).
- Toggling an option from `Yes` to `No` in a later `azd up` run is additive only and does **not** revoke prior assignments.
- Revocation/best-effort cleanup runs on `azd down` (predown hook).

What this does:

- runs preprovision checks/auth + interactive wizard
- provisions infra and runs postprovision setup + validation hooks

## Modes

- **Quick**: Container App Job + Storage
- **WebApp**: Quick + Web App (Entra auth restricted by security group)

Defaults:

- `PERMISSION_PROFILE=Extended`
- `WEB_APP_SKU=F1`
- resource group pattern: `rg-<environment>-<location>` (override with `AZURE_RESOURCE_GROUP`)

## Operations

- Remove environment + Azure resources (includes predown cleanup):
  `azd down -e <env> --force --purge`
- Optionally remove local azd env:
  `azd env remove <env> --force`

### Cleanup details

`azd down` runs `scripts/Run-AzdPreDown.ps1`, which performs best-effort cleanup for tenant/scope-level assignments created by advanced options, including:

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

- azd hooks: `scripts/Run-AzdPreUp.ps1`, `scripts/Run-AzdPreProvision.ps1`, `scripts/Run-AzdPostProvision.ps1`, `scripts/Run-AzdPreDown.ps1`
- Internal setup/validation: `scripts/Setup-PostDeploy.ps1`, `scripts/Invoke-JobValidation.ps1`
- Container runner script (uploaded to Azure Files): `scripts/Invoke-MaesterContainerJob.ps1`
- ACR image build: `scripts/Build-MaesterImage.ps1`, `Dockerfile`

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
