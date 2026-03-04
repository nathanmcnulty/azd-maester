# Shared preprovision helpers for azd-maester solutions.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Maester-UpWizard.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Maester-SetupHelpers.psm1') -Force

function Get-SemanticVersion {
  param([Parameter(Mandatory = $true)][string]$VersionText)

  $match = [regex]::Match($VersionText, '(\d+)\.(\d+)\.(\d+)')
  if (-not $match.Success) {
    return $null
  }

  return [version]::new([int]$match.Groups[1].Value, [int]$match.Groups[2].Value, [int]$match.Groups[3].Value)
}

function Invoke-MaesterPreProvision {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('automation-account', 'function-app', 'container-app-job', 'azure-devops')]
    [string]$SolutionName,

    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$Location,

    [Parameter(Mandatory = $false)]
    [switch]$RequireGit,

    [Parameter(Mandatory = $false)]
    [switch]$RequireAdopsModule,

    [Parameter(Mandatory = $false)]
    [switch]$RequireAdoToken,

    [Parameter(Mandatory = $false)]
    [switch]$RequireGraphProbe
  )

  if (-not $SubscriptionId) {
    $SubscriptionId = $env:AZURE_SUBSCRIPTION_ID
  }
  if (-not $TenantId -and $env:AZURE_TENANT_ID) {
    $TenantId = $env:AZURE_TENANT_ID
  }

  if (-not $SubscriptionId) {
    throw 'AZURE_SUBSCRIPTION_ID is required before provision. Run azd env set AZURE_SUBSCRIPTION_ID <subId> or create env with subscription.'
  }

  $azdVersionOutput = (& azd version) -join "`n"
  $detectedVersion = Get-SemanticVersion -VersionText $azdVersionOutput
  $minimumVersion = [version]::new(1, 23, 5)
  if (-not $detectedVersion) {
    Write-Warning 'Could not parse azd version. Continuing with preprovision checks.'
  }
  elseif ($detectedVersion -lt $minimumVersion) {
    throw "azd version $detectedVersion detected. Version 1.23.5 or newer is required for this template flow."
  }

  if ($RequireGit -and -not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'Git is required for Azure DevOps repository bootstrap but was not found on PATH.'
  }

  if ($RequireAdopsModule) {
    Import-Module (Join-Path $PSScriptRoot 'Maester-SetupHelpers.psm1') -Force

    $adopsInstallMessage = "PowerShell module 'ADOPS' is required for Azure DevOps integration. Install now to continue preprovision checks."
    if (-not (Test-ModuleAvailable -ModuleName 'ADOPS' -InstallMessage $adopsInstallMessage)) {
      throw "PowerShell module 'ADOPS' is required. Install with: Install-Module ADOPS -Scope CurrentUser -Force -AllowClobber"
    }
  }

  if ($SubscriptionId) { az account set --subscription $SubscriptionId 2>$null | Out-Null }
  $azAccount = az account show 2>$null | ConvertFrom-Json
  if (-not $azAccount) { throw 'Not authenticated. Run: azd auth login' }
  if (-not $SubscriptionId) { $SubscriptionId = $azAccount.id }
  if (-not $TenantId) { $TenantId = $azAccount.tenantId }

  if ([string]::IsNullOrWhiteSpace($TenantId)) {
    throw 'AZURE_TENANT_ID could not be resolved during preprovision.'
  }

  if ($RequireGraphProbe) {
    Assert-GraphAccess -TenantId $TenantId -Scopes 'Directory.Read.All'
  }
  else {
    Assert-GraphAccess -TenantId $TenantId -Scopes 'Directory.Read.All'
  }

  Invoke-MaesterUpWizard `
    -SolutionName $SolutionName `
    -SubscriptionId $SubscriptionId `
    -Location $Location `
    -TenantId $TenantId

  Write-Host 'Preprovision checks passed: azd version, Azure authentication, and preprovision prerequisites are ready.'
}

Export-ModuleMember -Function Invoke-MaesterPreProvision
