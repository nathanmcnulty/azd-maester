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

if (-not (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
  function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory = $true)]
      [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
      [string]$Method,

      [Parameter(Mandatory = $true)]
      [string]$Uri,

      [Parameter(Mandatory = $false)]
      $Body,

      [Parameter(Mandatory = $false)]
      [string]$ContentType = 'application/json'
    )

    $invokeParams = @{
      Method = $Method
      Uri    = $Uri
    }

    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
      if ($Body -is [string]) {
        $invokeParams['Payload'] = $Body
      }
      else {
        $invokeParams['Payload'] = ($Body | ConvertTo-Json -Depth 20)
      }
    }

    $response = Invoke-AzRestMethod @invokeParams
    if (-not $response) {
      return $null
    }

    if ($response.StatusCode -ge 400) {
      throw "Microsoft Graph request failed. HTTP $($response.StatusCode): $($response.Content)"
    }

    if ([string]::IsNullOrWhiteSpace($response.Content)) {
      return $null
    }

    return ($response.Content | ConvertFrom-Json)
  }
}

$graphProbe = Invoke-AzRestMethod -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id&$top=1'
if ($graphProbe.StatusCode -ge 400) {
  throw "Microsoft Graph access check failed while granting permissions. HTTP $($graphProbe.StatusCode): $($graphProbe.Content)"
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
