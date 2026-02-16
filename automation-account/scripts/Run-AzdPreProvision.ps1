[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$TenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

$azdVersionOutput = (& azd version) -join "`n"
$detectedVersion = Get-SemanticVersion -VersionText $azdVersionOutput
$minimumVersion = [version]::new(1, 23, 5)
if (-not $detectedVersion) {
  Write-Warning 'Could not parse azd version. Continuing with preprovision checks.'
}
elseif ($detectedVersion -lt $minimumVersion) {
  throw "azd version $detectedVersion detected. Version 1.23.5 or newer is required for this template flow."
}

Import-Module Az.Accounts -Force
Import-Module Microsoft.Graph.Authentication -Force

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

if (-not $TenantId) {
  $context = Get-AzContext
  if ($context -and $context.Tenant) {
    $TenantId = $context.Tenant.Id
  }
}

Connect-MgGraph -TenantId $TenantId -Scopes 'Directory.Read.All' -NoWelcome | Out-Null

Write-Host 'Preprovision checks passed: azd version, Azure authentication, and Graph authentication are ready.'