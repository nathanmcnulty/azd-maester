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
  [string]$MailRecipient = '',

  [Parameter(Mandatory = $false)]
  [Alias('Organization')]
  [string]$AdoOrganization,

  [Parameter(Mandatory = $false)]
  [Alias('Project')]
  [string]$AdoProject,

  [Parameter(Mandatory = $false)]
  [string]$AdoRepositoryName,

  [Parameter(Mandatory = $false)]
  [string]$AdoPipelineName = 'maester-weekly',

  [Parameter(Mandatory = $false)]
  [string]$AdoServiceConnectionName,

  [Parameter(Mandatory = $false)]
  [string]$PipelineYamlPath = '/azure-pipelines.yml',

  [Parameter(Mandatory = $false)]
  [string]$DefaultBranch = 'main',

  [Parameter(Mandatory = $false)]
  [string]$ScheduleCron = '0 0 * * 0',

  [Parameter(Mandatory = $false)]
  [bool]$CreateRepositoryIfMissing = $true,

  [Parameter(Mandatory = $false)]
  [bool]$PushPipelineFiles = $true,

  [Parameter(Mandatory = $false)]
  [bool]$ValidatePipelineRun = $true,

  [Parameter(Mandatory = $false)]
  [bool]$FailOnTestFailures = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-EnvValue {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Lines,

    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  foreach ($line in $Lines) {
    if ($line -like "$Name=*") {
      return $line.Split('=', 2)[1].Trim('"')
    }
  }

  return $null
}

function Resolve-RequiredTextValue {
  param(
    [Parameter(Mandatory = $true)]
    [string]$CurrentValue,

    [Parameter(Mandatory = $true)]
    [string]$PromptText,

    [Parameter(Mandatory = $true)]
    [string]$ErrorText
  )

  if (-not [string]::IsNullOrWhiteSpace($CurrentValue)) {
    return $CurrentValue.Trim()
  }

  $canPrompt = $false
  try {
    $null = $Host.UI.RawUI
    $canPrompt = $true
  }
  catch {
    $canPrompt = $false
  }

  if (-not $canPrompt) {
    throw $ErrorText
  }

  $enteredValue = Read-Host $PromptText
  if ([string]::IsNullOrWhiteSpace($enteredValue)) {
    throw $ErrorText
  }

  return $enteredValue.Trim()
}

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

if (-not (Test-CommandExists -CommandName 'git')) {
  throw 'Git is required but was not found on PATH.'
}

Confirm-AzureLogin
$effectiveSubscriptionId = Select-Subscription -RequestedSubscriptionId $SubscriptionId
$tenantId = az account show --query tenantId -o tsv
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($tenantId)) {
  throw 'Could not determine tenantId from Azure CLI context.'
}

if ([string]::IsNullOrWhiteSpace($EnvironmentName)) {
  $EnvironmentName = "maesterado{0}" -f (Get-Random -Minimum 1000 -Maximum 9999)
  Write-Host "Environment name not provided. Using generated name: $EnvironmentName"
}

$AdoOrganization = Resolve-RequiredTextValue -CurrentValue $AdoOrganization -PromptText 'Azure DevOps organization name (for https://dev.azure.com/<org>)' -ErrorText 'AdoOrganization is required. Pass -AdoOrganization <orgName>.'
$AdoProject = Resolve-RequiredTextValue -CurrentValue $AdoProject -PromptText 'Azure DevOps project name' -ErrorText 'AdoProject is required. Pass -AdoProject <projectName>.'

if ([string]::IsNullOrWhiteSpace($AdoRepositoryName)) {
  $AdoRepositoryName = "maester-$($EnvironmentName.ToLower())"
}

if ([string]::IsNullOrWhiteSpace($AdoServiceConnectionName)) {
  $AdoServiceConnectionName = "sc-maester-$($EnvironmentName.ToLower())"
}

$normalizedLocation = ($Location -replace '\s+', '').ToLower()
$effectiveResourceGroupName = if (-not [string]::IsNullOrWhiteSpace($ResourceGroupName)) {
  $ResourceGroupName
}
else {
  "rg-$($EnvironmentName.ToLower())-$normalizedLocation"
}

$initializeArgs = @{
  EnvironmentName            = $EnvironmentName
  SubscriptionId             = $effectiveSubscriptionId
  Location                   = $Location
  ResourceGroupName          = $effectiveResourceGroupName
  IncludeWebApp              = [bool]$IncludeWebApp
  IncludeExchange            = [bool]$IncludeExchange
  IncludeTeams               = [bool]$IncludeTeams
  IncludeAzure               = [bool]$IncludeAzure
  WebAppSku                  = $WebAppSku
  PermissionProfile          = $PermissionProfile
  TenantId                   = $tenantId
  MailRecipient              = $MailRecipient
  AdoOrganization            = $AdoOrganization
  AdoProject                 = $AdoProject
  AdoRepositoryName          = $AdoRepositoryName
  AdoPipelineName            = $AdoPipelineName
  AdoServiceConnectionName   = $AdoServiceConnectionName
  PipelineYamlPath           = $PipelineYamlPath
  DefaultBranch              = $DefaultBranch
  ScheduleCron               = $ScheduleCron
  CreateRepositoryIfMissing  = $CreateRepositoryIfMissing
  PushPipelineFiles          = $PushPipelineFiles
  ValidatePipelineRun        = $ValidatePipelineRun
  FailOnTestFailures         = $FailOnTestFailures
}

if ($IncludeAzure -and (-not $AzureScopes -or $AzureScopes.Count -eq 0)) {
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
    }
    catch {
    }
  }

  if (-not $AzureScopes -or $AzureScopes.Count -eq 0) {
    $AzureScopes = Select-AzureRbacScopes -DefaultSubscriptionId $effectiveSubscriptionId -ResourceTypeName 'Azure DevOps workload identity'
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

Write-Host 'Provisioning Azure resources and configuring Azure DevOps...'
& azd provision --no-prompt --no-state
if ($LASTEXITCODE -ne 0) {
  Write-Host ''
  Write-Host 'Provisioning failed. Querying deployment error details...' -ForegroundColor Red
  try {
    $deploymentJson = az deployment group list --resource-group $effectiveResourceGroupName --query "sort_by([?properties.provisioningState=='Failed'], &properties.timestamp) | [-1]" -o json 2>$null
    if ($LASTEXITCODE -eq 0 -and $deploymentJson) {
      $deployment = $deploymentJson | ConvertFrom-Json
      if ($deployment -and $deployment.properties.error) {
        Write-Host "  Deployment: $($deployment.name)" -ForegroundColor Yellow
        Write-Host "  Error Code: $($deployment.properties.error.code)" -ForegroundColor Yellow
        Write-Host "  Error Message: $($deployment.properties.error.message)" -ForegroundColor Yellow
        if ($deployment.properties.error.details) {
          foreach ($detail in $deployment.properties.error.details) {
            Write-Host "  -> [$($detail.code)] $($detail.message)" -ForegroundColor Yellow
          }
        }
      }
    }
  }
  catch {
    Write-Host '  Could not retrieve deployment error details.' -ForegroundColor DarkYellow
  }
  throw 'azd provision failed. See error details above.'
}

$pipelineUrl = $null
$webHostName = $null
$envValuesText = azd env get-values
foreach ($line in $envValuesText) {
  if ($line -like 'AZDO_PIPELINE_URL=*') {
    $pipelineUrl = $line.Split('=', 2)[1].Trim('"')
  }
  if ($line -like 'webAppDefaultHostName=*') {
    $webHostName = $line.Split('=', 2)[1].Trim('"')
  }
}

Write-Host "Completed. Environment: $EnvironmentName"
Write-Host "Azure DevOps organization: $AdoOrganization"
Write-Host "Azure DevOps project: $AdoProject"
Write-Host "Azure DevOps repository: $AdoRepositoryName"
if (-not [string]::IsNullOrWhiteSpace($pipelineUrl)) {
  Write-Host "Pipeline URL: $pipelineUrl" -ForegroundColor Cyan
}
if (-not [string]::IsNullOrWhiteSpace($webHostName)) {
  Write-Host "Web app URL: https://$webHostName/" -ForegroundColor Cyan
}
Write-Host 'Schedule: Runs every Sunday at 00:00 UTC by default. Update -ScheduleCron to customize.' -ForegroundColor DarkCyan
