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
  [Alias('WebApp')]
  [switch]$IncludeWebApp,

  [Parameter(Mandatory = $false)]
  [string]$SecurityGroupObjectId,

  [Parameter(Mandatory = $false)]
  [string]$SecurityGroupDisplayName,

  [Parameter(Mandatory = $false)]
  [string]$WebAppSku = 'F1',

  [Parameter(Mandatory = $false)]
  [ValidateSet('Minimal', 'Extended')]
  [string]$PermissionProfile = 'Extended'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($IncludeWebApp -and [string]::IsNullOrWhiteSpace($SecurityGroupObjectId)) {
  throw 'SecurityGroupObjectId is required when -IncludeWebApp is specified.'
}

function Test-CommandExists {
  param([Parameter(Mandatory = $true)][string]$CommandName)
  return [bool](Get-Command -Name $CommandName -ErrorAction SilentlyContinue)
}

function Ensure-AzureLogin {
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

if (-not (Test-CommandExists -CommandName 'az')) {
  throw 'Azure CLI (az) is required but was not found on PATH.'
}

if (-not (Test-CommandExists -CommandName 'azd')) {
  throw 'Azure Developer CLI (azd) is required but was not found on PATH.'
}

Ensure-AzureLogin
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
  WebAppSku         = $WebAppSku
  PermissionProfile = $PermissionProfile
  TenantId          = $tenantId
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
  Write-Host "Web app URL: https://$webHostName/"
}