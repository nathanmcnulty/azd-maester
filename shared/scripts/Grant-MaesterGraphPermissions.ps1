[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$TenantId,

  [Parameter(Mandatory = $true)]
  [string]$PrincipalObjectId,

  [Parameter(Mandatory = $false)]
  [ValidateSet('Minimal', 'Extended')]
  [string]$PermissionProfile = 'Extended',

  [Parameter(Mandatory = $false)]
  [string[]]$AppRoleValues,

  [Parameter(Mandatory = $false)]
  [bool]$IncludeMailSend = $true
)

$minimalAppRoleValues = @(
  'Directory.Read.All',
  'DirectoryRecommendations.Read.All',
  'IdentityRiskEvent.Read.All',
  'Policy.Read.All',
  'Policy.Read.ConditionalAccess',
  'RoleManagement.Read.All',
  'Reports.Read.All',
  'UserAuthenticationMethod.Read.All'
)

$extendedAppRoleValues = @(
  'DeviceManagementConfiguration.Read.All',
  'DeviceManagementServiceConfig.Read.All',
  'DeviceManagementManagedDevices.Read.All',
  'DeviceManagementRBAC.Read.All',
  'PrivilegedAccess.Read.AzureAD',
  'ReportSettings.Read.All',
  'RoleEligibilitySchedule.Read.Directory',
  'SecurityIdentitiesHealth.Read.All',
  'SecurityIdentitiesSensors.Read.All',
  'SharePointTenantSettings.Read.All',
  'ThreatHunting.Read.All'
)

if (-not $PSBoundParameters.ContainsKey('AppRoleValues')) {
  $profileRoles = @()
  if ($PermissionProfile -eq 'Minimal') {
    $profileRoles = @($minimalAppRoleValues)
  }
  else {
    $profileRoles = @($minimalAppRoleValues + $extendedAppRoleValues)
  }

  if ($IncludeMailSend) {
    $profileRoles += 'Mail.Send'
  }

  $AppRoleValues = $profileRoles
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Maester-SetupHelpers.psm1') -Force
Assert-GraphAccess -TenantId $TenantId -Scopes 'Application.Read.All','AppRoleAssignment.ReadWrite.All','Directory.Read.All','Directory.AccessAsUser.All'

$graphServicePrincipal = Invoke-GraphRestRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'"
if (-not $graphServicePrincipal.value -or $graphServicePrincipal.value.Count -eq 0) {
  throw 'Microsoft Graph service principal was not found in this tenant.'
}

$resourceServicePrincipal = $graphServicePrincipal.value[0]
$appRoles = @($resourceServicePrincipal.appRoles | Where-Object { $_.value -and $_.allowedMemberTypes -contains 'Application' })

$existingAssignments = Invoke-GraphRestRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalObjectId/appRoleAssignments?`$top=999"
$existingAssignmentList = @($existingAssignments.value)

foreach ($appRoleValue in $AppRoleValues) {
  $match = $appRoles | Where-Object { $_.value -eq $appRoleValue }
  if (-not $match) {
    throw "App role '$appRoleValue' was not found on Microsoft Graph service principal."
  }

  $alreadyAssigned = @($existingAssignmentList | Where-Object { $_.resourceId -eq $resourceServicePrincipal.id -and $_.appRoleId -eq $match.id })
  if ($alreadyAssigned.Count -gt 0) {
    Write-Host "App role '$appRoleValue' already assigned."
    continue
  }

  $body = @{
    principalId = $PrincipalObjectId
    resourceId  = $resourceServicePrincipal.id
    appRoleId   = $match.id
  } | ConvertTo-Json

  Invoke-GraphRestRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalObjectId/appRoleAssignments" -Body $body -ContentType 'application/json'
  Write-Host "Assigned app role '$appRoleValue'."
}

Write-Host 'Graph app role assignment completed.'
