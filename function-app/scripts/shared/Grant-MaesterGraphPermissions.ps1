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
  [string[]]$AppRoleValues
)

$minimalAppRoleValues = @(
  'Directory.Read.All',
  'DirectoryRecommendations.Read.All',
  'IdentityRiskEvent.Read.All',
  'Mail.Send',
  'Policy.Read.All',
  'Policy.Read.ConditionalAccess',
  'RoleManagement.Read.All',
  'Reports.Read.All',
  'UserAuthenticationMethod.Read.All'
)

$extendedAppRoleValues = @(
  'DeviceManagementConfiguration.Read.All',
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
  if ($PermissionProfile -eq 'Minimal') {
    $AppRoleValues = $minimalAppRoleValues
  }
  else {
    $AppRoleValues = @($minimalAppRoleValues + $extendedAppRoleValues)
  }
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module Az.Accounts -Force
Import-Module Microsoft.Graph.Authentication -Force

$graphToken = $null
try {
  $tokenJson = az account get-access-token --resource https://graph.microsoft.com -o json 2>$null
  if ($LASTEXITCODE -eq 0 -and $tokenJson) {
    $tokenData = $tokenJson | ConvertFrom-Json
    $graphToken = $tokenData.accessToken
  }
}
catch {
  Write-Verbose "az cli token acquisition failed for Graph: $($_.Exception.Message)"
}

if ($graphToken) {
  $secureToken = ConvertTo-SecureString $graphToken -AsPlainText -Force
  Connect-MgGraph -AccessToken $secureToken -NoWelcome
}
else {
  Connect-MgGraph -TenantId $TenantId -Scopes 'Application.Read.All','AppRoleAssignment.ReadWrite.All','Directory.Read.All','Directory.AccessAsUser.All' -NoWelcome
}

$graphServicePrincipal = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'"
if (-not $graphServicePrincipal.value -or $graphServicePrincipal.value.Count -eq 0) {
  throw 'Microsoft Graph service principal was not found in this tenant.'
}

$resourceServicePrincipal = $graphServicePrincipal.value[0]
$appRoles = @($resourceServicePrincipal.appRoles | Where-Object { $_.value -and $_.allowedMemberTypes -contains 'Application' })

$existingAssignments = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalObjectId/appRoleAssignments?`$top=999"
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

  Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalObjectId/appRoleAssignments" -Body $body -ContentType 'application/json'
  Write-Host "Assigned app role '$appRoleValue'."
}

Write-Host 'Graph app role assignment completed.'
