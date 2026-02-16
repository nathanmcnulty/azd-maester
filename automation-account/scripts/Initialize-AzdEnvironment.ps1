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
  [ValidateSet('Quick', 'Advanced')]
  [string]$DeploymentMode = 'Quick',

  [Parameter(Mandatory = $false)]
  [bool]$IncludeWebApp,

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
  $IncludeWebApp = $DeploymentMode -eq 'Advanced'
}

if (-not $PSBoundParameters.ContainsKey('PermissionProfile') -or [string]::IsNullOrWhiteSpace($PermissionProfile)) {
  $PermissionProfile = 'Extended'
}

if ($IncludeWebApp -and [string]::IsNullOrWhiteSpace($SecurityGroupObjectId) -and -not [string]::IsNullOrWhiteSpace($SecurityGroupDisplayName)) {
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

  if (-not $TenantId) {
    $context = Get-AzContext
    if ($context -and $context.Tenant) {
      $TenantId = $context.Tenant.Id
    }
  }

  Connect-MgGraph -TenantId $TenantId -Scopes 'Group.Read.All','Directory.Read.All' -NoWelcome | Out-Null

  $escapedDisplayName = [System.Uri]::EscapeDataString("'$SecurityGroupDisplayName'")
  $groupsResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq $escapedDisplayName&`$select=id,displayName,description&`$top=25"
  $foundGroups = @($groupsResponse.value)

  if ($foundGroups.Count -eq 0) {
    throw "No Entra security groups found with display name '$SecurityGroupDisplayName'."
  }

  if ($foundGroups.Count -eq 1) {
    $SecurityGroupObjectId = $foundGroups[0].id
    Write-Host "Resolved security group '$SecurityGroupDisplayName' to object ID '$SecurityGroupObjectId'."
  }
  else {
    $canPrompt = $false
    try {
      $null = $Host.UI.RawUI
      $canPrompt = $true
    }
    catch {
      $canPrompt = $false
    }

    if (-not $canPrompt) {
      throw "Multiple Entra security groups matched '$SecurityGroupDisplayName'. Re-run with -SecurityGroupObjectId to avoid ambiguity."
    }

    Write-Host "Multiple groups matched '$SecurityGroupDisplayName'. Select one:"
    for ($index = 0; $index -lt $foundGroups.Count; $index++) {
      $item = $foundGroups[$index]
      $description = if ($item.description) { $item.description } else { 'n/a' }
      Write-Host ("[{0}] {1} ({2})" -f ($index + 1), $item.displayName, $description)
    }

    $selection = Read-Host 'Enter selection number'
    $selectionValue = 0
    if (-not [int]::TryParse($selection, [ref]$selectionValue)) {
      throw 'Selection was not a valid number.'
    }

    $selectionIndex = $selectionValue - 1
    if ($selectionIndex -lt 0 -or $selectionIndex -ge $foundGroups.Count) {
      throw 'Selection is out of range.'
    }

    $SecurityGroupObjectId = $foundGroups[$selectionIndex].id
    Write-Host "Selected security group object ID: $SecurityGroupObjectId"
  }
}

if ($IncludeWebApp -and [string]::IsNullOrWhiteSpace($SecurityGroupObjectId)) {
  throw 'SecurityGroupObjectId (or SecurityGroupDisplayName) is required when IncludeWebApp is true.'
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
Invoke-Azd -Arguments @('env', 'set', 'DEPLOYMENT_MODE', $DeploymentMode.ToLower()) -Operation 'set deployment mode'
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
Write-Host "Deployment mode: $DeploymentMode"
Write-Host "Permission profile: $PermissionProfile"
Write-Host 'Validate on provision: true'
Write-Host 'Next command: azd provision --no-prompt --no-state'