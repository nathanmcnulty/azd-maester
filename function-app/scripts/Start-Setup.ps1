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
  [ValidateSet('Minimal', 'Extended')]
  [string]$PermissionProfile = 'Extended',

  [Parameter(Mandatory = $false)]
  [ValidateSet('FC1', 'B1', 'Y1')]
  [string]$Plan = 'FC1',

  [Parameter(Mandatory = $false)]
  [string]$MailRecipient = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot
Import-Module "$PSScriptRoot\shared\Maester-SetupHelpers.psm1" -Force

if ($IncludeWebApp -and [string]::IsNullOrWhiteSpace($SecurityGroupObjectId)) {
  throw 'SecurityGroupObjectId is required when -IncludeWebApp is specified.'
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
  WebAppSku         = $WebAppSku
  PermissionProfile = $PermissionProfile
  TenantId          = $tenantId
  Plan              = $Plan
  MailRecipient     = $MailRecipient
}

if ($IncludeAzure -and (-not $AzureScopes -or $AzureScopes.Count -eq 0)) {
  # On re-runs with a known environment, reuse previously stored scopes without re-prompting
  if (-not [string]::IsNullOrWhiteSpace($EnvironmentName)) {
    try {
      $existingLines = & azd env get-values --environment $EnvironmentName 2>$null
      if ($LASTEXITCODE -eq 0 -and $existingLines) {
        foreach ($line in $existingLines) {
          if ($line -like 'AZURE_RBAC_SCOPES=*') {
            $raw = $line.Split('=', 2)[1].Trim('"')
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
              $AzureScopes = @($raw -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
              Write-Host "Reusing existing Azure RBAC scopes from environment '$EnvironmentName': $($AzureScopes -join '; ')"
            }
            break
          }
        }
      }
    } catch {}
  }
  if (-not $AzureScopes -or $AzureScopes.Count -eq 0) {
    $AzureScopes = Select-AzureRbacScopes -DefaultSubscriptionId $effectiveSubscriptionId -ResourceTypeName 'Function App'
  }
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
  # Extract deployment error details from the resource group
  Write-Host ''
  Write-Host 'Provisioning failed. Querying deployment error details...' -ForegroundColor Red
  try {
    $deploymentJson = az deployment group list --resource-group $effectiveResourceGroupName --query "sort_by([?properties.provisioningState=='Failed'], &properties.timestamp) | [-1]" -o json 2>$null
    if ($LASTEXITCODE -eq 0 -and $deploymentJson) {
      $deployment = $deploymentJson | ConvertFrom-Json
      if ($deployment -and $deployment.properties.error) {
        $errCode = $deployment.properties.error.code
        $errMsg = $deployment.properties.error.message
        Write-Host "  Deployment: $($deployment.name)" -ForegroundColor Yellow
        Write-Host "  Error Code: $errCode" -ForegroundColor Yellow
        Write-Host "  Error Message: $errMsg" -ForegroundColor Yellow
        # Show sub-errors if present
        if ($deployment.properties.error.details) {
          foreach ($detail in $deployment.properties.error.details) {
            Write-Host "  -> [$($detail.code)] $($detail.message)" -ForegroundColor Yellow
          }
        }
      }
    }
  } catch {
    Write-Host '  Could not retrieve deployment error details.' -ForegroundColor DarkYellow
  }
  throw 'azd provision failed. See error details above.'
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
Write-Host 'Schedule: Runs every Sunday at midnight UTC. See README.md for instructions on customizing the schedule.' -ForegroundColor DarkCyan
