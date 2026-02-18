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
  [switch]$IncludeExchange,

  [Parameter(Mandatory = $false)]
  [switch]$IncludeTeams,

  [Parameter(Mandatory = $false)]
  [switch]$IncludeAzure,

  [Parameter(Mandatory = $false)]
  [string[]]$AzureScopes,

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

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot

if (-not $PSBoundParameters.ContainsKey('IncludeWebApp')) {
  $IncludeWebApp = $false
}

if (-not $PSBoundParameters.ContainsKey('IncludeExchange')) {
  $IncludeExchange = $false
}

if (-not $PSBoundParameters.ContainsKey('IncludeTeams')) {
  $IncludeTeams = $false
}

if (-not $PSBoundParameters.ContainsKey('IncludeAzure')) {
  $IncludeAzure = $false
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

$envNewOutput = & azd env new $EnvironmentName --subscription $SubscriptionId --location $Location --no-prompt 2>&1
if ($LASTEXITCODE -ne 0) {
  $alreadyExists = $envNewOutput | Where-Object { $_ -match 'already exists' }
  if ($alreadyExists) {
    Write-Host "Environment '$EnvironmentName' already exists. Selecting it."
  }
  else {
    $envNewOutput | ForEach-Object { Write-Host $_ }
    throw "azd env new failed for environment '$EnvironmentName'."
  }
  Invoke-Azd -Arguments @('env', 'select', $EnvironmentName) -Operation 'env select existing environment'
}

Invoke-Azd -Arguments @('env', 'set', 'AZURE_RESOURCE_GROUP', $resourceGroupName) -Operation 'set resource group'
Invoke-Azd -Arguments @('env', 'set', 'INCLUDE_WEB_APP', $IncludeWebApp.ToString().ToLower()) -Operation 'set include web app'
Invoke-Azd -Arguments @('env', 'set', 'INCLUDE_EXCHANGE', $IncludeExchange.ToString().ToLower()) -Operation 'set include exchange'
Invoke-Azd -Arguments @('env', 'set', 'INCLUDE_TEAMS', $IncludeTeams.ToString().ToLower()) -Operation 'set include teams'
Invoke-Azd -Arguments @('env', 'set', 'INCLUDE_AZURE', $IncludeAzure.ToString().ToLower()) -Operation 'set include azure'
Invoke-Azd -Arguments @('env', 'set', 'WEB_APP_SKU', $WebAppSku) -Operation 'set web app sku'
Invoke-Azd -Arguments @('env', 'set', 'PERMISSION_PROFILE', $PermissionProfile) -Operation 'set permission profile'
Invoke-Azd -Arguments @('env', 'set', 'VALIDATE_RUNBOOK_ON_PROVISION', 'true') -Operation 'set postprovision runbook validation'

$effectiveAzureScopes = @()
if ($IncludeAzure -and $AzureScopes -and $AzureScopes.Count -gt 0) {
  $effectiveAzureScopes = @($AzureScopes)
}

$azureScopesSerialized = (@($effectiveAzureScopes) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) -join ';'
Invoke-Azd -Arguments @('env', 'set', 'AZURE_RBAC_SCOPES', $azureScopesSerialized) -Operation 'set azure rbac scopes'

if ($IncludeWebApp) {
  Invoke-Azd -Arguments @('env', 'set', 'SECURITY_GROUP_OBJECT_ID', $SecurityGroupObjectId) -Operation 'set security group'
  if (-not [string]::IsNullOrWhiteSpace($SecurityGroupDisplayName)) {
    Invoke-Azd -Arguments @('env', 'set', 'SECURITY_GROUP_DISPLAY_NAME', $SecurityGroupDisplayName) -Operation 'set security group display name'
  }
}

Write-Host "Environment '$EnvironmentName' is ready."
Write-Host "Resource group: $resourceGroupName"
Write-Host ("Web app enabled: {0}" -f $IncludeWebApp.ToString().ToLower())
Write-Host ("Include Exchange: {0}" -f $IncludeExchange.ToString().ToLower())
Write-Host ("Include Teams: {0}" -f $IncludeTeams.ToString().ToLower())
Write-Host ("Include Azure: {0}" -f $IncludeAzure.ToString().ToLower())
Write-Host "Azure RBAC scopes: $azureScopesSerialized"
Write-Host "Permission profile: $PermissionProfile"
Write-Host 'Validate on provision: true'
Write-Host 'Next command: azd provision --no-prompt --no-state'