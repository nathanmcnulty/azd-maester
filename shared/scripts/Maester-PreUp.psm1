# Shared preup helpers for azd-maester solutions.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Maester-Helpers.psm1') -Force

function Get-ValueFromEnvironmentOrAzd {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [hashtable]$AzdValues
  )

  $fromEnvironment = [Environment]::GetEnvironmentVariable($Name)
  if (-not [string]::IsNullOrWhiteSpace($fromEnvironment)) {
    return $fromEnvironment
  }

  return (Get-AzdEnvironmentValue -Values $AzdValues -Name $Name)
}

function Invoke-MaesterPreUp {
  [CmdletBinding()]
  param()

  $envValues = Get-AzdEnvironmentValues

  $resourceGroupName = Get-ValueFromEnvironmentOrAzd -Name 'AZURE_RESOURCE_GROUP' -AzdValues $envValues
  if ([string]::IsNullOrWhiteSpace($resourceGroupName)) {
    return
  }

  $subscriptionId = Get-ValueFromEnvironmentOrAzd -Name 'AZURE_SUBSCRIPTION_ID' -AzdValues $envValues
  if ([string]::IsNullOrWhiteSpace($subscriptionId)) {
    $subscriptionId = (& az account show --query id -o tsv 2>$null)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($subscriptionId)) {
      throw "AZURE_SUBSCRIPTION_ID is required to resolve resource group '$resourceGroupName'."
    }
  }

  $exists = (& az group exists --name $resourceGroupName --subscription $subscriptionId -o tsv 2>$null)
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($exists)) {
    throw "Failed to check whether resource group '$resourceGroupName' exists."
  }

  if ($exists.Trim().ToLowerInvariant() -eq 'true') {
    Write-Host "Using existing resource group '$resourceGroupName'."
    return
  }

  $location = Get-ValueFromEnvironmentOrAzd -Name 'AZURE_LOCATION' -AzdValues $envValues
  if ([string]::IsNullOrWhiteSpace($location)) {
    throw "AZURE_LOCATION is required to create resource group '$resourceGroupName'."
  }

  Write-Host "Creating resource group '$resourceGroupName' in '$location'..."
  & az group create --name $resourceGroupName --location $location --subscription $subscriptionId --output none
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to create resource group '$resourceGroupName'."
  }

  Write-Host "Created resource group '$resourceGroupName'."
}

Export-ModuleMember -Function Invoke-MaesterPreUp
