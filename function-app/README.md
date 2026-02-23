# Function App azd solution

Deploys a production-style Maester automation solution on Azure with:

- Azure Function App (PowerShell 7.4, Consumption plan, timer-triggered)
- Managed identity + Graph permissions
- Managed dependencies for automatic module installation
- Storage-backed report history (`archive`) and latest pointer (`latest/latest.html`)
- Optional App Service + Easy Auth portal in WebApp mode

## Quickstart (recommended)

After `azd init -t <your-template-id>` and `cd function-app`, run one command:

`./scripts/Start-Setup.ps1 -IncludeWebApp -SecurityGroupObjectId <groupObjectId>`

For quick mode (no web app), run with no mode flags:

`./scripts/Start-Setup.ps1`

## Advanced options (optional)

You can optionally enable additional data collection/connectivity for Maester by enabling one or more `-Include*` switches during setup.

- `-IncludeExchange`
  - Ensures the `ExchangeOnlineManagement` module is available at runtime (via managed dependencies).
  - Grants the Function App managed identity the Exchange app permission required for app-only Exchange Online access.
  - Creates/links an Exchange service principal for the managed identity and assigns the Exchange RBAC role `View-Only Configuration` (best-effort).
- `-IncludeTeams`
  - Ensures the `MicrosoftTeams` module is available at runtime (via managed dependencies).
  - Assigns the Entra directory role `Teams Reader` to the Function App managed identity.
- `-IncludeAzure`
  - Grants Azure RBAC `Reader` to the Function App managed identity at one or more scopes.
  - Scopes can be management groups and/or subscriptions.

Examples:

- Enable Exchange + Teams:
  - `./scripts/Start-Setup.ps1 -IncludeExchange -IncludeTeams`
- Enable Azure and select scopes interactively:
  - `./scripts/Start-Setup.ps1 -IncludeAzure`
- Enable Azure with explicit scopes:
  - `./scripts/Start-Setup.ps1 -IncludeAzure -AzureScopes '/providers/Microsoft.Management/managementGroups/<mgName>','/subscriptions/<subId>'`
- Full options:
  - `./scripts/Start-Setup.ps1 -IncludeWebApp -IncludeExchange -IncludeTeams -IncludeAzure -SecurityGroupObjectId <groupObjectId>`

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

- **Quick**: Function App + Storage
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
│ Azure Functions (Consumption Plan Y1)                            │
│   ┌────────────────────────────────────────────────────────┐     │
│   │ Function App (PowerShell 7.4, Linux)                   │     │
│   │ Timer trigger: Sunday midnight UTC                     │     │
│   │ Managed dependencies (modules auto-installed)          │     │
│   │ MI: System-Assigned                                    │     │
│   │ Timeout: 10 minutes                                    │     │
│   └──────┬─────────────────────────────────────────────────┘     │
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
    └─────────────────────────────────────────────────────┘
```

## Script map

- User entry point: `scripts/Start-Setup.ps1`
- Environment setup: `scripts/Initialize-AzdEnvironment.ps1`
- azd hooks: `scripts/Run-AzdPreProvision.ps1`, `scripts/Run-AzdPostProvision.ps1`
- Internal setup/validation: `scripts/Setup-PostDeploy.ps1`, `scripts/Invoke-FunctionValidation.ps1`
- Function deployment: `scripts/Deploy-FunctionCode.ps1`
- Teardown: `scripts/Remove-AzdEnvironment.ps1`

## Runtime behavior

- Weekly schedule (Sunday midnight UTC). To run at a different time or frequency, edit the `schedule` value in `src/MaesterTimerTrigger/function.json` (e.g. `"0 30 6 * * 1"` for Monday 6:30 UTC), then re-deploy the function code.
- Consumption plan (Y1): pay-per-execution, auto-scale, 10-minute max timeout
- Managed dependencies: modules defined in `requirements.psd1` are auto-installed by the platform
- Runner script: `src/MaesterTimerTrigger/run.ps1`
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
- Function App identity uses `Website Contributor` (least privilege for web content publish) on the optional Web App

## Security recommendations

This solution is reasonably secure, but there are additional controls you may choose to implement based on your organization requirements:

- **Storage private networking:** Use Private Endpoint + storage firewall rules to restrict data plane access to approved networks only.
- **Function App networking:** Use VNet integration and private endpoints for network isolation.
- **Web App private networking:** Use App Service Private Endpoint and access restrictions if your organization requires private-only ingress.
- **Centralized logging:** Send resource logs/metrics to a central Log Analytics workspace (or SIEM) for audit and incident response.
- **Conditional Access:** Apply tenant-wide baseline Conditional Access policies for user sign-in controls (MFA, device/risk posture).

## Reference docs

- Azure Developer CLI overview: https://learn.microsoft.com/azure/developer/azure-developer-cli/
- azd templates: https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-templates
- azd hooks/extensibility: https://learn.microsoft.com/azure/developer/azure-developer-cli/azd-extensibility
- Manage azd environment variables: https://learn.microsoft.com/azure/developer/azure-developer-cli/manage-environment-variables
- Azure Functions hosting options: https://learn.microsoft.com/azure/azure-functions/functions-scale
- Azure Functions PowerShell guide: https://learn.microsoft.com/azure/azure-functions/functions-reference-powershell
- Azure Functions managed dependencies: https://learn.microsoft.com/azure/azure-functions/functions-reference-powershell#dependency-management
- App Service custom domain: https://learn.microsoft.com/azure/app-service/app-service-web-tutorial-custom-domain
