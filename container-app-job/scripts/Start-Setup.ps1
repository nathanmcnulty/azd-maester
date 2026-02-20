[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$EnvironmentName,

  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$Location = 'eastus2',

  [Parameter(Mandatory = $false)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $false)]
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
  [string]$SecurityGroupObjectId,

  [Parameter(Mandatory = $false)]
  [string]$SecurityGroupDisplayName,

  [Parameter(Mandatory = $false)]
  [string]$WebAppSku = 'F1',

  [Parameter(Mandatory = $false)]
  [Alias('ACR')]
  [switch]$IncludeACR,

  [Parameter(Mandatory = $false)]
  [ValidateSet('Minimal', 'Extended')]
  [string]$PermissionProfile = 'Extended'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot

if ($IncludeWebApp -and [string]::IsNullOrWhiteSpace($SecurityGroupObjectId)) {
  throw 'SecurityGroupObjectId is required when -IncludeWebApp is specified.'
}

function Test-CommandExists {
  param([Parameter(Mandatory = $true)][string]$CommandName)
  return [bool](Get-Command -Name $CommandName -ErrorAction SilentlyContinue)
}

function Confirm-AzureLogin {
  try {
    $null = az account show --output none 2>$null
    if ($LASTEXITCODE -eq 0) {
      return
    }
  }
  catch {
  }

  Write-Host 'No active Azure CLI login detected. Opening Azure login...'
  & az login | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw 'Azure login failed.'
  }
}

function Select-Subscription {
  param([Parameter(Mandatory = $false)][string]$RequestedSubscriptionId)

  if (-not [string]::IsNullOrWhiteSpace($RequestedSubscriptionId)) {
    & az account set --subscription $RequestedSubscriptionId
    if ($LASTEXITCODE -ne 0) {
      throw "Could not select subscription '$RequestedSubscriptionId'."
    }
    return $RequestedSubscriptionId
  }

  $subscriptionsJson = az account list --query "[].{name:name,id:id,isDefault:isDefault,tenantId:tenantId}" -o json
  if ($LASTEXITCODE -ne 0) {
    throw 'Failed to enumerate subscriptions.'
  }

  $subscriptions = $subscriptionsJson | ConvertFrom-Json
  if (-not $subscriptions -or $subscriptions.Count -eq 0) {
    throw 'No Azure subscriptions available for the signed-in account.'
  }

  if ($subscriptions.Count -eq 1) {
    $singleId = $subscriptions[0].id
    Write-Host "Using only available subscription: $($subscriptions[0].name) ($singleId)"
    & az account set --subscription $singleId
    if ($LASTEXITCODE -ne 0) {
      throw "Could not select subscription '$singleId'."
    }
    return $singleId
  }

  Write-Host 'Select a subscription:'
  for ($index = 0; $index -lt $subscriptions.Count; $index++) {
    $sub = $subscriptions[$index]
    $defaultMarker = if ($sub.isDefault) { ' (default)' } else { '' }
    Write-Host ("[{0}] {1} | {2}{3}" -f ($index + 1), $sub.name, $sub.id, $defaultMarker)
  }

  $selection = Read-Host 'Enter selection number'
  $selectionValue = 0
  if (-not [int]::TryParse($selection, [ref]$selectionValue)) {
    throw 'Subscription selection must be a number.'
  }

  $selectedIndex = $selectionValue - 1
  if ($selectedIndex -lt 0 -or $selectedIndex -ge $subscriptions.Count) {
    throw 'Subscription selection is out of range.'
  }

  $selectedId = $subscriptions[$selectedIndex].id
  & az account set --subscription $selectedId
  if ($LASTEXITCODE -ne 0) {
    throw "Could not select subscription '$selectedId'."
  }

  return $selectedId
}

function Test-CanPrompt {
  try {
    $null = $Host.UI.RawUI
    return $true
  }
  catch {
    return $false
  }
}

function Select-AzureRbacScopes {
  param(
    [Parameter(Mandatory = $true)]
    [string]$DefaultSubscriptionId
  )

  if (-not (Test-CanPrompt)) {
    Write-Warning "-IncludeAzure was specified but interactive prompting is not available. Defaulting Azure RBAC scope to subscription '/subscriptions/$DefaultSubscriptionId'."
    return @("/subscriptions/$DefaultSubscriptionId")
  }

  $items = @()

  try {
    $mgJson = & az account management-group list -o json 2>$null
    if ($LASTEXITCODE -eq 0 -and $mgJson) {
      $mgs = $mgJson | ConvertFrom-Json
      foreach ($mg in @($mgs)) {
        $mgName = if ($mg.name) { $mg.name } elseif ($mg.id -and ($mg.id -split '/')[-1]) { ($mg.id -split '/')[-1] } else { $null }
        if (-not $mgName) { continue }
        $mgDisplayName = if ($mg.displayName) { $mg.displayName } else { $mgName }
        $items += [pscustomobject]@{
          Label = "MG  | $mgDisplayName ($mgName)"
          Scope = "/providers/Microsoft.Management/managementGroups/$mgName"
        }
      }
    }
  }
  catch {
  }

  $subsJson = az account list --query "[].{name:name,id:id,isDefault:isDefault}" -o json
  if ($LASTEXITCODE -ne 0) {
    throw 'Failed to enumerate subscriptions for Azure scope selection.'
  }

  $subs = $subsJson | ConvertFrom-Json
  foreach ($sub in @($subs)) {
    $items += [pscustomobject]@{
      Label = "SUB | $($sub.name) ($($sub.id))"
      Scope = "/subscriptions/$($sub.id)"
    }
  }

  if ($items.Count -eq 0) {
    Write-Warning "No management groups or subscriptions were discovered. Defaulting Azure RBAC scope to subscription '/subscriptions/$DefaultSubscriptionId'."
    return @("/subscriptions/$DefaultSubscriptionId")
  }

  Write-Host 'Select one or more Azure RBAC scopes to grant the Container App Job managed identity Reader access.'
  Write-Host 'Enter one or more numbers separated by commas. Press Enter to use the current subscription.'
  for ($index = 0; $index -lt $items.Count; $index++) {
    Write-Host ("[{0}] {1}" -f ($index + 1), $items[$index].Label)
  }

  $selection = Read-Host 'Selection'
  if ([string]::IsNullOrWhiteSpace($selection)) {
    return @("/subscriptions/$DefaultSubscriptionId")
  }

  $selectedScopes = @()
  $parts = @($selection -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  foreach ($part in $parts) {
    $value = 0
    if (-not [int]::TryParse($part, [ref]$value)) {
      throw "Invalid selection '$part'. Expected a number or comma-separated numbers."
    }

    $selectedIndex = $value - 1
    if ($selectedIndex -lt 0 -or $selectedIndex -ge $items.Count) {
      throw "Selection '$value' is out of range."
    }

    $selectedScopes += $items[$selectedIndex].Scope
  }

  return @($selectedScopes | Sort-Object -Unique)
}

if (-not (Test-CommandExists -CommandName 'az')) {
  throw 'Azure CLI (az) is required but was not found on PATH.'
}

if (-not (Test-CommandExists -CommandName 'azd')) {
  throw 'Azure Developer CLI (azd) is required but was not found on PATH.'
}

Confirm-AzureLogin
$effectiveSubscriptionId = Select-Subscription -RequestedSubscriptionId $SubscriptionId
$tenantId = az account show --query tenantId -o tsv
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($tenantId)) {
  throw 'Could not determine tenantId from Azure CLI context.'
}

if ([string]::IsNullOrWhiteSpace($EnvironmentName)) {
  $modePrefix = if ($IncludeWebApp) { 'maesterweb' } else { 'maesterqk' }
  $EnvironmentName = "{0}{1}" -f $modePrefix, (Get-Random -Minimum 1000 -Maximum 9999)
  Write-Host "Environment name not provided. Using generated name: $EnvironmentName"
}

$normalizedLocation = ($Location -replace '\s+', '').ToLower()
$effectiveResourceGroupName = if (-not [string]::IsNullOrWhiteSpace($ResourceGroupName)) {
  $ResourceGroupName
}
else {
  "rg-$($EnvironmentName.ToLower())-$normalizedLocation"
}

$initializeArgs = @{
  EnvironmentName   = $EnvironmentName
  SubscriptionId    = $effectiveSubscriptionId
  Location          = $Location
  ResourceGroupName = $effectiveResourceGroupName
  IncludeWebApp     = [bool]$IncludeWebApp
  IncludeExchange   = [bool]$IncludeExchange
  IncludeTeams      = [bool]$IncludeTeams
  IncludeAzure      = [bool]$IncludeAzure
  IncludeACR        = [bool]$IncludeACR
  WebAppSku         = $WebAppSku
  PermissionProfile = $PermissionProfile
  TenantId          = $tenantId
}

if ($IncludeAzure -and (-not $AzureScopes -or $AzureScopes.Count -eq 0)) {
  $AzureScopes = Select-AzureRbacScopes -DefaultSubscriptionId $effectiveSubscriptionId
}

if ($AzureScopes -and $AzureScopes.Count -gt 0) {
  $initializeArgs['AzureScopes'] = @($AzureScopes)
}

if (-not [string]::IsNullOrWhiteSpace($SecurityGroupObjectId)) {
  $initializeArgs['SecurityGroupObjectId'] = $SecurityGroupObjectId
}
if (-not [string]::IsNullOrWhiteSpace($SecurityGroupDisplayName)) {
  $initializeArgs['SecurityGroupDisplayName'] = $SecurityGroupDisplayName
}

Write-Host 'Initializing azd environment...'
& "$PSScriptRoot\Initialize-AzdEnvironment.ps1" @initializeArgs

Write-Host "Ensuring resource group exists: $effectiveResourceGroupName"
& az group create --name $effectiveResourceGroupName --location $Location --output none
if ($LASTEXITCODE -ne 0) {
  throw "Failed to create or access resource group '$effectiveResourceGroupName'."
}

Write-Host 'Provisioning Azure resources...'
& azd provision --no-prompt --no-state
if ($LASTEXITCODE -ne 0) {
  throw 'azd provision failed.'
}

$envValuesText = azd env get-values
$webHostName = $null
foreach ($line in $envValuesText) {
  if ($line -like 'webAppDefaultHostName=*') {
    $valuePart = $line.Split('=', 2)[1]
    $webHostName = $valuePart.Trim('"')
    break
  }
}

Write-Host "Completed. Environment: $EnvironmentName"
if (-not [string]::IsNullOrWhiteSpace($webHostName)) {
  Write-Host "Web app URL: https://$webHostName/" -ForegroundColor Cyan
}
