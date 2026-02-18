[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$TenantId,

  [Parameter(Mandatory = $false)]
  [string]$EnvironmentName,

  [Parameter(Mandatory = $false)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $false)]
  [string]$SecurityGroupObjectId,

  [Parameter(Mandatory = $false)]
  [string]$SecurityGroupDisplayName,

  [Parameter(Mandatory = $false)]
  [ValidateSet('Minimal', 'Extended')]
  [string]$PermissionProfile = 'Extended'
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

Import-Module Az.Accounts -Force

if (-not $SubscriptionId) {
  $SubscriptionId = $env:AZURE_SUBSCRIPTION_ID
}
if (-not $TenantId -and $env:AZURE_TENANT_ID) {
  $TenantId = $env:AZURE_TENANT_ID
}
if (-not $EnvironmentName) {
  $EnvironmentName = if ($env:AZURE_ENV_NAME) { $env:AZURE_ENV_NAME } else { 'dev' }
}
if (-not $ResourceGroupName) {
  $ResourceGroupName = if ($env:AZURE_RESOURCE_GROUP) { $env:AZURE_RESOURCE_GROUP } else { "rg-$EnvironmentName" }
}
if (-not $SecurityGroupObjectId) {
  if ($env:SECURITY_GROUP_OBJECT_ID) {
    $SecurityGroupObjectId = $env:SECURITY_GROUP_OBJECT_ID
  }
  elseif ($env:EASY_AUTH_SECURITY_GROUP_OBJECT_ID) {
    $SecurityGroupObjectId = $env:EASY_AUTH_SECURITY_GROUP_OBJECT_ID
  }
}
if (-not $SecurityGroupDisplayName -and $env:SECURITY_GROUP_DISPLAY_NAME) {
  $SecurityGroupDisplayName = $env:SECURITY_GROUP_DISPLAY_NAME
}
if (-not $PSBoundParameters.ContainsKey('PermissionProfile') -and $env:PERMISSION_PROFILE) {
  $PermissionProfile = $env:PERMISSION_PROFILE
}

Write-Host 'Running postprovision setup...'

$setupParams = @{
  SubscriptionId    = $SubscriptionId
  EnvironmentName   = $EnvironmentName
  ResourceGroupName = $ResourceGroupName
  PermissionProfile = $PermissionProfile
}
if ($TenantId) {
  $setupParams['TenantId'] = $TenantId
}
if ($SecurityGroupObjectId) {
  $setupParams['SecurityGroupObjectId'] = $SecurityGroupObjectId
}
if ($SecurityGroupDisplayName) {
  $setupParams['SecurityGroupDisplayName'] = $SecurityGroupDisplayName
}

& "$PSScriptRoot\Setup-PostDeploy.ps1" @setupParams

$easyAuthAppObjectId = 'n/a'
$easyAuthAppClientIdFromEnv = 'n/a'
$easyAuthAppDisplayName = 'n/a'
$includeExchangeFromEnv = 'n/a'
$includeTeamsFromEnv = 'n/a'
$includeAzureFromEnv = 'n/a'
$azureScopesFromEnv = 'n/a'
$exchangeSetupStatusFromEnv = 'n/a'
$teamsSetupStatusFromEnv = 'n/a'
$azureSetupStatusFromEnv = 'n/a'
$exoAppRoleAssignmentIdsFromEnv = 'n/a'
$teamsRoleAssignmentIdsFromEnv = 'n/a'
$azureRoleAssignmentIdsFromEnv = 'n/a'
$exoServicePrincipalDisplayNameFromEnv = 'n/a'
$envValues = & azd env get-values
if ($LASTEXITCODE -eq 0) {
  $easyAuthAppObjectIdValue = Get-EnvValue -Lines $envValues -Name 'EASY_AUTH_ENTRA_APP_OBJECT_ID'
  $easyAuthAppClientIdValue = Get-EnvValue -Lines $envValues -Name 'EASY_AUTH_ENTRA_APP_CLIENT_ID'
  $easyAuthAppDisplayNameValue = Get-EnvValue -Lines $envValues -Name 'EASY_AUTH_ENTRA_APP_DISPLAY_NAME'

  if (-not [string]::IsNullOrWhiteSpace($easyAuthAppObjectIdValue)) {
    $easyAuthAppObjectId = $easyAuthAppObjectIdValue
  }
  if (-not [string]::IsNullOrWhiteSpace($easyAuthAppClientIdValue)) {
    $easyAuthAppClientIdFromEnv = $easyAuthAppClientIdValue
  }
  if (-not [string]::IsNullOrWhiteSpace($easyAuthAppDisplayNameValue)) {
    $easyAuthAppDisplayName = $easyAuthAppDisplayNameValue
  }

  $includeExchangeValue = Get-EnvValue -Lines $envValues -Name 'INCLUDE_EXCHANGE'
  $includeTeamsValue = Get-EnvValue -Lines $envValues -Name 'INCLUDE_TEAMS'
  $includeAzureValue = Get-EnvValue -Lines $envValues -Name 'INCLUDE_AZURE'
  $azureScopesValue = Get-EnvValue -Lines $envValues -Name 'AZURE_RBAC_SCOPES'
  $exchangeStatusValue = Get-EnvValue -Lines $envValues -Name 'SETUP_EXCHANGE_STATUS'
  $teamsStatusValue = Get-EnvValue -Lines $envValues -Name 'SETUP_TEAMS_STATUS'
  $azureStatusValue = Get-EnvValue -Lines $envValues -Name 'SETUP_AZURE_STATUS'
  $exoAppRoleIdsValue = Get-EnvValue -Lines $envValues -Name 'EXO_APPROLE_ASSIGNMENT_IDS'
  $teamsRoleIdsValue = Get-EnvValue -Lines $envValues -Name 'TEAMS_READER_ROLE_ASSIGNMENT_IDS'
  $azureRoleIdsValue = Get-EnvValue -Lines $envValues -Name 'AZURE_ROLE_ASSIGNMENT_IDS'
  $exoSpDisplayNameValue = Get-EnvValue -Lines $envValues -Name 'EXO_SERVICE_PRINCIPAL_DISPLAY_NAME'

  if (-not [string]::IsNullOrWhiteSpace($includeExchangeValue)) { $includeExchangeFromEnv = $includeExchangeValue }
  if (-not [string]::IsNullOrWhiteSpace($includeTeamsValue)) { $includeTeamsFromEnv = $includeTeamsValue }
  if (-not [string]::IsNullOrWhiteSpace($includeAzureValue)) { $includeAzureFromEnv = $includeAzureValue }
  if (-not [string]::IsNullOrWhiteSpace($azureScopesValue)) { $azureScopesFromEnv = $azureScopesValue }
  if (-not [string]::IsNullOrWhiteSpace($exchangeStatusValue)) { $exchangeSetupStatusFromEnv = $exchangeStatusValue }
  if (-not [string]::IsNullOrWhiteSpace($teamsStatusValue)) { $teamsSetupStatusFromEnv = $teamsStatusValue }
  if (-not [string]::IsNullOrWhiteSpace($azureStatusValue)) { $azureSetupStatusFromEnv = $azureStatusValue }
  if (-not [string]::IsNullOrWhiteSpace($exoAppRoleIdsValue)) { $exoAppRoleAssignmentIdsFromEnv = $exoAppRoleIdsValue }
  if (-not [string]::IsNullOrWhiteSpace($teamsRoleIdsValue)) { $teamsRoleAssignmentIdsFromEnv = $teamsRoleIdsValue }
  if (-not [string]::IsNullOrWhiteSpace($azureRoleIdsValue)) { $azureRoleAssignmentIdsFromEnv = $azureRoleIdsValue }
  if (-not [string]::IsNullOrWhiteSpace($exoSpDisplayNameValue)) { $exoServicePrincipalDisplayNameFromEnv = $exoSpDisplayNameValue }
}

Write-Host 'Running postprovision runbook validation...'

$automationAccountName = "aa-$($EnvironmentName.ToLower())"
$testParams = @{
  SubscriptionId       = $SubscriptionId
  ResourceGroupName    = $ResourceGroupName
  AutomationAccountName = $automationAccountName
  RunbookName          = 'maester-runbook'
}
if ($TenantId) {
  $testParams['TenantId'] = $TenantId
}

$testParams['PassThru'] = $true

$validationResult = & "$PSScriptRoot\Invoke-RunbookValidation.ps1" @testParams

$resourcesPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/resources?api-version=2021-04-01"
$resourcesPayload = (Invoke-AzRestMethod -Method GET -Path $resourcesPath).Content | ConvertFrom-Json
$resources = @($resourcesPayload.value)
$customDnsDocsUrl = 'https://learn.microsoft.com/azure/app-service/app-service-web-tutorial-custom-domain'

$automationResource = $resources | Where-Object { $_.type -eq 'Microsoft.Automation/automationAccounts' } | Select-Object -First 1
$storageResource = $resources | Where-Object { $_.type -eq 'Microsoft.Storage/storageAccounts' } | Select-Object -First 1
$webAppResource = $resources | Where-Object { $_.type -eq 'Microsoft.Web/sites' } | Select-Object -First 1
$planResource = $resources | Where-Object { $_.type -eq 'Microsoft.Web/serverfarms' } | Select-Object -First 1
$includeWebAppEffective = [bool]$webAppResource
$deploymentModeEffective = if ($includeWebAppEffective) { 'webapp' } else { 'quick' }

$summaryDir = Join-Path -Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path -ChildPath 'outputs'
if (-not (Test-Path -Path $summaryDir)) {
  New-Item -Path $summaryDir -ItemType Directory -Force | Out-Null
}

$summaryPath = Join-Path -Path $summaryDir -ChildPath ("{0}-setup-summary.md" -f $EnvironmentName)
$summaryLines = @()
$summaryLines += '# Deployment and Validation Summary'
$summaryLines += ""
$summaryLines += "Generated: $(Get-Date -Format u)"
$summaryLines += "Environment: $EnvironmentName"
$summaryLines += "Subscription: $SubscriptionId"
$summaryLines += "Resource group: $ResourceGroupName"
$summaryLines += "Deployment mode: $deploymentModeEffective"
$summaryLines += "Include web app: $($includeWebAppEffective.ToString().ToLower())"
$summaryLines += "Include Exchange: $includeExchangeFromEnv"
$summaryLines += "Include Teams: $includeTeamsFromEnv"
$summaryLines += "Include Azure: $includeAzureFromEnv"
$summaryLines += "Permission profile: $PermissionProfile"
$summaryLines += "Azure RBAC scopes: $azureScopesFromEnv"
$summaryLines += "Exchange setup status: $exchangeSetupStatusFromEnv"
$summaryLines += "Teams setup status: $teamsSetupStatusFromEnv"
$summaryLines += "Azure setup status: $azureSetupStatusFromEnv"
$summaryLines += "Exchange appRoleAssignment ids: $exoAppRoleAssignmentIdsFromEnv"
$summaryLines += "Teams roleAssignment ids: $teamsRoleAssignmentIdsFromEnv"
$summaryLines += "Azure roleAssignment ids: $azureRoleAssignmentIdsFromEnv"
$summaryLines += "Exchange SP display name: $exoServicePrincipalDisplayNameFromEnv"
$summaryLines += "Security group object id: $(if ($SecurityGroupObjectId) { $SecurityGroupObjectId } else { 'n/a' })"
$summaryLines += "Security group display name: $(if ($SecurityGroupDisplayName) { $SecurityGroupDisplayName } else { 'n/a' })"
$easyAuthClientId = 'n/a'
$easyAuthIssuer = 'n/a'
if ($webAppResource) {
  $authPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$($webAppResource.name)/config/authsettingsV2?api-version=2023-12-01"
  $auth = (Invoke-AzRestMethod -Method GET -Path $authPath).Content | ConvertFrom-Json
  if ($auth.properties.identityProviders.azureActiveDirectory.registration.clientId) {
    $easyAuthClientId = $auth.properties.identityProviders.azureActiveDirectory.registration.clientId
  }
  if ($auth.properties.identityProviders.azureActiveDirectory.registration.openIdIssuer) {
    $easyAuthIssuer = $auth.properties.identityProviders.azureActiveDirectory.registration.openIdIssuer
  }
}
$effectiveEasyAuthClientId = if ($easyAuthClientId -and $easyAuthClientId -ne 'n/a') { $easyAuthClientId } else { $easyAuthAppClientIdFromEnv }
$summaryLines += "Easy Auth clientId: $easyAuthClientId"
$summaryLines += "Easy Auth issuer: $easyAuthIssuer"
$summaryLines += "Easy Auth Entra app objectId: $easyAuthAppObjectId"
$summaryLines += "Easy Auth Entra app display name: $easyAuthAppDisplayName"
$summaryLines += "Easy Auth Entra app clientId (azd env): $easyAuthAppClientIdFromEnv"
$summaryLines += "Easy Auth effective clientId: $effectiveEasyAuthClientId"
$summaryLines += ""
$summaryLines += '## Resources Created'
$summaryLines += "- Automation Account: $(if ($automationResource) { $automationResource.name } else { 'not found' })"
$summaryLines += "- Storage Account: $(if ($storageResource) { $storageResource.name } else { 'not found' })"
$summaryLines += "- App Service Plan: $(if ($planResource) { $planResource.name } else { 'not deployed' })"
$summaryLines += "- Web App: $(if ($webAppResource) { $webAppResource.name } else { 'not deployed' })"
$summaryLines += ""
$summaryLines += '## How Components Interoperate'
$summaryLines += '- Automation runbook executes Maester tests on the weekly schedule and on-demand validation runs.'
$summaryLines += '- Automation managed identity calls Microsoft Graph using the configured permission profile.'
$summaryLines += '- Automation managed identity uploads gzip-compressed dated reports to storage container `archive` and `latest.html` to `latest`.'
if ($webAppResource) {
  $summaryLines += '- Web App hosts the latest dashboard experience and is protected by Easy Auth + Entra security group restriction.'
  $summaryLines += "- Optional custom DNS setup guidance: $customDnsDocsUrl"
}
else {
  $summaryLines += '- Web App is not deployed in quick mode; reports remain available through storage-backed workflow.'
}
$summaryLines += ""
$summaryLines += '## Validation Results'
$summaryLines += "- Runbook validation status: $(if ($validationResult.ValidationPassed) { 'Passed' } else { 'Failed' })"
$summaryLines += "- Runbook job id: $($validationResult.JobId)"
$summaryLines += "- Runbook final status: $($validationResult.FinalStatus)"
$summaryLines += "- Validation completed at: $($validationResult.CompletedAt)"

Set-Content -Path $summaryPath -Value ($summaryLines -join [Environment]::NewLine) -Encoding utf8

Write-Host "Deployment summary written to: $summaryPath"

if ($webAppResource) {
  Write-Host "Optional custom DNS setup guide: $customDnsDocsUrl"
}

Write-Host 'azd postprovision automation completed successfully.'