[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$EnvironmentName,

  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$Location = 'eastus2',

  [Parameter(Mandatory = $false)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $false)]
  [Alias('WebApp')]
  [switch]$IncludeWebApp,

  [Parameter(Mandatory = $false)]
  [string]$WebAppSku = 'F1',

  [Parameter(Mandatory = $false)]
  [ValidateSet('Minimal', 'Extended')]
  [string]$PermissionProfile,

  [Parameter(Mandatory = $false)]
  [string]$SecurityGroupObjectId,

  [Parameter(Mandatory = $false)]
  [string]$SecurityGroupDisplayName,

  [Parameter(Mandatory = $false)]
  [string]$TenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $PSBoundParameters.ContainsKey('IncludeWebApp')) {
  $IncludeWebApp = $false
}

if (-not $PSBoundParameters.ContainsKey('PermissionProfile') -or [string]::IsNullOrWhiteSpace($PermissionProfile)) {
  $PermissionProfile = 'Extended'
}

if ($IncludeWebApp -and [string]::IsNullOrWhiteSpace($SecurityGroupObjectId)) {
  throw 'SecurityGroupObjectId is required when IncludeWebApp is true.'
}

$normalizedLocation = ($Location -replace '\s+', '').ToLower()
$resourceGroupName = if (-not [string]::IsNullOrWhiteSpace($ResourceGroupName)) {
  $ResourceGroupName
}
else {
  "rg-$($EnvironmentName.ToLower())-$normalizedLocation"
}

function Invoke-Azd {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments,

    [Parameter(Mandatory = $true)]
    [string]$Operation
  )

  & azd @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "azd command failed during: $Operation"
  }
}

$envCreated = $true
& azd env new $EnvironmentName --subscription $SubscriptionId --location $Location --no-prompt
if ($LASTEXITCODE -ne 0) {
  $envCreated = $false
}

if (-not $envCreated) {
  Invoke-Azd -Arguments @('env', 'select', $EnvironmentName) -Operation 'env select existing environment'
}

Invoke-Azd -Arguments @('env', 'set', 'AZURE_RESOURCE_GROUP', $resourceGroupName) -Operation 'set resource group'
Invoke-Azd -Arguments @('env', 'set', 'INCLUDE_WEB_APP', $IncludeWebApp.ToString().ToLower()) -Operation 'set include web app'
Invoke-Azd -Arguments @('env', 'set', 'WEB_APP_SKU', $WebAppSku) -Operation 'set web app sku'
Invoke-Azd -Arguments @('env', 'set', 'PERMISSION_PROFILE', $PermissionProfile) -Operation 'set permission profile'
Invoke-Azd -Arguments @('env', 'set', 'VALIDATE_RUNBOOK_ON_PROVISION', 'true') -Operation 'set postprovision runbook validation'

if ($IncludeWebApp) {
  Invoke-Azd -Arguments @('env', 'set', 'SECURITY_GROUP_OBJECT_ID', $SecurityGroupObjectId) -Operation 'set security group'
  if (-not [string]::IsNullOrWhiteSpace($SecurityGroupDisplayName)) {
    Invoke-Azd -Arguments @('env', 'set', 'SECURITY_GROUP_DISPLAY_NAME', $SecurityGroupDisplayName) -Operation 'set security group display name'
  }
}

Write-Host "Environment '$EnvironmentName' is ready."
Write-Host "Resource group: $resourceGroupName"
Write-Host ("Web app enabled: {0}" -f $IncludeWebApp.ToString().ToLower())
Write-Host "Permission profile: $PermissionProfile"
Write-Host 'Validate on provision: true'
Write-Host 'Next command: azd provision --no-prompt --no-state'