[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$EnvironmentName,

  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$TenantId,

  [Parameter(Mandatory = $false)]
  [string]$Location = 'eastus2',

  [Parameter(Mandatory = $false)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $false)]
  [bool]$IncludeWebApp = $true,

  [Parameter(Mandatory = $false)]
  [string]$WebAppSku = 'F1',

  [Parameter(Mandatory = $false)]
  [string]$SecurityGroupObjectId,

  [Parameter(Mandatory = $false)]
  [string]$MailRecipient = '',

  [Parameter(Mandatory = $false)]
  [ValidateSet('Minimal', 'Extended')]
  [string]$PermissionProfile = 'Extended'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($IncludeWebApp -and [string]::IsNullOrWhiteSpace($SecurityGroupObjectId)) {
  throw 'SecurityGroupObjectId is required when IncludeWebApp is true.'
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot

$normalizedLocation = ($Location -replace '\s+', '').ToLower()
$resourceGroupName = if (-not [string]::IsNullOrWhiteSpace($ResourceGroupName)) {
  $ResourceGroupName
}
else {
  "rg-$($EnvironmentName.ToLower())-$normalizedLocation"
}
$automationAccountName = "aa-$($EnvironmentName.ToLower())"

Write-Host 'Step 1/5: Initialize azd environment defaults'
$deploymentMode = if ($IncludeWebApp) { 'Advanced' } else { 'Quick' }
& "$PSScriptRoot\Initialize-AzdEnvironment.ps1" `
  -EnvironmentName $EnvironmentName `
  -SubscriptionId $SubscriptionId `
  -Location $Location `
  -ResourceGroupName $resourceGroupName `
  -DeploymentMode $deploymentMode `
  -IncludeWebApp $IncludeWebApp `
  -WebAppSku $WebAppSku `
  -PermissionProfile $PermissionProfile `
  -SecurityGroupObjectId $SecurityGroupObjectId

if (-not [string]::IsNullOrWhiteSpace($MailRecipient)) {
  & azd env set MAIL_RECIPIENT $MailRecipient
  if ($LASTEXITCODE -ne 0) {
    throw 'Failed to set MAIL_RECIPIENT in azd environment.'
  }
}

Write-Host "Ensuring resource group exists: $resourceGroupName"
& az group create --name $resourceGroupName --location $Location --output none
if ($LASTEXITCODE -ne 0) {
  throw "Failed to create or access resource group '$resourceGroupName'."
}

Write-Host 'Step 2/5: Provision infrastructure'
& azd provision --no-prompt --no-state
if ($LASTEXITCODE -ne 0) {
  throw 'azd provision failed.'
}

Write-Host 'Step 3/5: Postprovision hook ran setup + validation'
Write-Host 'Step 4/5: Asserting deployed configuration'
Import-Module Az.Accounts -Force

$existingContext = Get-AzContext -ErrorAction SilentlyContinue
$requiresLogin = $true
if ($existingContext -and $existingContext.Subscription -and $existingContext.Subscription.Id -eq $SubscriptionId) {
  if (-not $TenantId -or ($existingContext.Tenant -and $existingContext.Tenant.Id -eq $TenantId)) {
    $requiresLogin = $false
  }
}

if ($requiresLogin) {
  Connect-AzAccount -Subscription $SubscriptionId -Tenant $TenantId | Out-Null
}

try {
  Get-AzAccessToken -ResourceTypeName Arm | Out-Null
}
catch {
  Connect-AzAccount -Subscription $SubscriptionId -Tenant $TenantId | Out-Null
}

$resourcesPath = "/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/resources?api-version=2021-04-01"
$resources = (Invoke-AzRestMethod -Method GET -Path $resourcesPath).Content | ConvertFrom-Json

$storage = $resources.value | Where-Object { $_.type -eq 'Microsoft.Storage/storageAccounts' } | Select-Object -First 1
if (-not $storage) {
  throw 'Storage account was not found in resource group.'
}

$signedInUserObjectId = (& az ad signed-in-user show --query id -o tsv).Trim()
if ([string]::IsNullOrWhiteSpace($signedInUserObjectId)) {
  throw 'Could not resolve signed-in user object ID for RBAC assertion.'
}

$blobReaderRoleDefinitionId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
$roleAssignmentsPath = "/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$($storage.name)/providers/Microsoft.Authorization/roleAssignments?`$filter=atScope()&api-version=2022-04-01"
$roleAssignments = (Invoke-AzRestMethod -Method GET -Path $roleAssignmentsPath).Content | ConvertFrom-Json
$signedInUserReaderAssignment = @($roleAssignments.value | Where-Object {
    $_.properties.principalId -eq $signedInUserObjectId -and $_.properties.roleDefinitionId -eq $blobReaderRoleDefinitionId
  }) | Select-Object -First 1
if (-not $signedInUserReaderAssignment) {
  throw "Signed-in user '$signedInUserObjectId' is missing Storage Blob Data Reader on storage account '$($storage.name)'."
}

$schedulesPath = "/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Automation/automationAccounts/$automationAccountName/schedules?api-version=2023-11-01"
$schedules = (Invoke-AzRestMethod -Method GET -Path $schedulesPath).Content | ConvertFrom-Json
$weeklySunday = $schedules.value | Where-Object { $_.properties.frequency -eq 'Week' -and $_.properties.advancedSchedule.weekDays -contains 'Sunday' } | Select-Object -First 1
if (-not $weeklySunday) {
  throw 'Weekly Sunday schedule was not found.'
}

$runtimePath = "/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Automation/automationAccounts/$automationAccountName/runtimeEnvironments?api-version=2024-10-23"
$runtime = (Invoke-AzRestMethod -Method GET -Path $runtimePath).Content | ConvertFrom-Json
$runtime74 = $runtime.value | Where-Object { $_.properties.runtime.language -eq 'PowerShell' -and $_.properties.runtime.version -eq '7.4' -and $_.name -eq 'PowerShell-74-Maester' } | Select-Object -First 1
if (-not $runtime74) {
  throw 'Custom PowerShell 7.4 runtime environment PowerShell-74-Maester was not found.'
}

$runbookPath = "/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Automation/automationAccounts/$automationAccountName/runbooks/maester-runbook?api-version=2024-10-23"
$runbook = (Invoke-AzRestMethod -Method GET -Path $runbookPath).Content | ConvertFrom-Json
if ($runbook.properties.runtimeEnvironment -ne 'PowerShell-74-Maester') {
  throw "Runbook runtimeEnvironment is '$($runbook.properties.runtimeEnvironment)', expected 'PowerShell-74-Maester'."
}

$containersPath = "/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$($storage.name)/blobServices/default/containers?api-version=2023-05-01"
$containers = (Invoke-AzRestMethod -Method GET -Path $containersPath).Content | ConvertFrom-Json
$containerNames = @($containers.value.name)
$requiredContainers = @('archive', 'latest')
$missingContainers = @($requiredContainers | Where-Object { $_ -notin $containerNames })
if (@($missingContainers).Count -gt 0) {
  throw "Missing required blob containers: $($missingContainers -join ', ')"
}

if ($IncludeWebApp) {
  $web = $resources.value | Where-Object { $_.type -eq 'Microsoft.Web/sites' } | Select-Object -First 1
  if (-not $web) {
    throw 'Web App was expected but not found.'
  }

  $authPath = "/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Web/sites/$($web.name)/config/authsettingsV2?api-version=2023-12-01"
  $auth = (Invoke-AzRestMethod -Method GET -Path $authPath).Content | ConvertFrom-Json
  if (-not $auth.properties.identityProviders.azureActiveDirectory.enabled) {
    throw 'Easy Auth Azure AD provider is not enabled.'
  }

  $groups = @($auth.properties.identityProviders.azureActiveDirectory.validation.defaultAuthorizationPolicy.allowedPrincipals.groups)
  if ($groups -notcontains $SecurityGroupObjectId) {
    throw 'Easy Auth allowed groups does not contain the expected security group object ID.'
  }
}

Write-Host 'Step 5/5: Confirming summary output'
$summaryPath = Join-Path -Path (Join-Path $projectRoot 'outputs') -ChildPath ("{0}-setup-summary.md" -f $EnvironmentName)
if (-not (Test-Path -Path $summaryPath)) {
  throw "Expected deployment summary was not found: $summaryPath"
}

Write-Host 'Deployment verification completed successfully.'
Write-Host "Environment: $EnvironmentName"
Write-Host "Resource group: $resourceGroupName"
Write-Host "Summary: $summaryPath"