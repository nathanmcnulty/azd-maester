[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$TenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot/shared/Maester-SetupHelpers.psm1" -Force

function Get-SemanticVersion {
  param([Parameter(Mandatory = $true)][string]$VersionText)

  $match = [regex]::Match($VersionText, '(\d+)\.(\d+)\.(\d+)')
  if (-not $match.Success) {
    return $null
  }

  return [version]::new([int]$match.Groups[1].Value, [int]$match.Groups[2].Value, [int]$match.Groups[3].Value)
}

if (-not $SubscriptionId) {
  $SubscriptionId = $env:AZURE_SUBSCRIPTION_ID
}
if (-not $TenantId -and $env:AZURE_TENANT_ID) {
  $TenantId = $env:AZURE_TENANT_ID
}

if (-not $SubscriptionId) {
  throw 'AZURE_SUBSCRIPTION_ID is required before provision. Run azd env set AZURE_SUBSCRIPTION_ID <subId> or create env with subscription.'
}

if ([string]::IsNullOrWhiteSpace($env:AZDO_ORGANIZATION)) {
  throw 'AZDO_ORGANIZATION is required before provision. Run Initialize-AzdEnvironment.ps1 or azd env set AZDO_ORGANIZATION <orgName>.'
}
if ([string]::IsNullOrWhiteSpace($env:AZDO_PROJECT)) {
  throw 'AZDO_PROJECT is required before provision. Run Initialize-AzdEnvironment.ps1 or azd env set AZDO_PROJECT <projectName>.'
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

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  throw 'Git is required for Azure DevOps repository bootstrap but was not found on PATH.'
}

Import-Module Az.Accounts -Force

$adopsInstallMessage = "PowerShell module 'ADOPS' is required for Azure DevOps integration. Install now to continue preprovision checks."
if (-not (Test-ModuleAvailable -ModuleName 'ADOPS' -InstallMessage $adopsInstallMessage)) {
  throw "PowerShell module 'ADOPS' is required. Install with: Install-Module ADOPS -Scope CurrentUser -Force -AllowClobber"
}

$existingContext = Get-AzContext -ErrorAction SilentlyContinue
$requiresLogin = $true
if ($existingContext -and $existingContext.Subscription -and $existingContext.Subscription.Id -eq $SubscriptionId) {
  if (-not $TenantId -or ($existingContext.Tenant -and $existingContext.Tenant.Id -eq $TenantId)) {
    $requiresLogin = $false
  }
}

if ($requiresLogin) {
  $connectParameters = @{ Subscription = $SubscriptionId }
  if ($TenantId) {
    $connectParameters['Tenant'] = $TenantId
  }
  Connect-AzAccount @connectParameters | Out-Null
}

Get-AzAccessToken -ResourceTypeName Arm | Out-Null
Get-AzAccessToken -ResourceUrl '499b84ac-1321-427f-aa17-267ca6975798' | Out-Null

if (-not $TenantId) {
  $context = Get-AzContext
  if ($context -and $context.Tenant) {
    $TenantId = $context.Tenant.Id
  }
}

$graphProbe = Invoke-AzRestMethod -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id&$top=1'
if ($graphProbe.StatusCode -ge 400) {
  throw "Microsoft Graph access check failed during preprovision. HTTP $($graphProbe.StatusCode): $($graphProbe.Content)"
}

Write-Host 'Preprovision checks passed: azd version, Azure authentication, Graph authentication, ADOPS module, and Azure DevOps access token are ready.'

