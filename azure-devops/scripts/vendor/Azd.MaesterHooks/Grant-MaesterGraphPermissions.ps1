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

# Complete enumeration is required before any grant decision. Never send a token
# to a continuation outside this principal's Microsoft Graph collection.
function Get-MaesterGraphAssignmentList {
  param([string]$TenantId, [string]$PrincipalObjectId)

  $collectionUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalObjectId/appRoleAssignments"
  $nextUri = "${collectionUri}?`$top=999"
  $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
  $assignments = [System.Collections.Generic.List[object]]::new()
  while ($nextUri) {
    $pageUri = $null
    if (-not [uri]::TryCreate($nextUri, [UriKind]::Absolute, [ref]$pageUri) -or
        $pageUri.Scheme -ne 'https' -or $pageUri.Host -ne 'graph.microsoft.com' -or
        $pageUri.Port -ne 443 -or $pageUri.UserInfo -or $pageUri.Fragment -or
        $pageUri.AbsolutePath -cne ([uri]$collectionUri).AbsolutePath) {
      throw 'Graph assignment continuation does not target the expected secure collection.'
    }
    if ($visited.Count -ge 100 -or -not $visited.Add($nextUri)) {
      throw 'Graph assignment pagination exceeded its limit or repeated a page.'
    }
    $page = Invoke-GraphRestRequest -Method GET -Uri $nextUri -TenantId $TenantId
    if ($null -eq $page -or -not $page.PSObject.Properties['value'] -or $null -eq $page.value) {
      throw 'Graph assignment response is missing its value collection.'
    }
    foreach ($assignment in @($page.value)) {
      $assignments.Add($assignment)
    }
    $nextUri = if ($page.PSObject.Properties['@odata.nextLink']) { [string]$page.'@odata.nextLink' } else { $null }
  }
  return $assignments.ToArray()
}

if ([string]::IsNullOrWhiteSpace($TenantId)) { throw 'TenantId must identify the selected deployment tenant.' }
$principalGuid = [guid]::Empty
if (-not [guid]::TryParse($PrincipalObjectId, [ref]$principalGuid) -or $principalGuid -eq [guid]::Empty) {
  throw 'PrincipalObjectId must be a non-empty GUID.'
}
$PrincipalObjectId = $principalGuid.ToString()

Import-Module (Join-Path $PSScriptRoot 'Maester-SetupHelpers.psm1') -Force
Assert-GraphAccess -TenantId $TenantId -Scopes 'Application.Read.All','AppRoleAssignment.ReadWrite.All','Directory.Read.All','Directory.AccessAsUser.All'

$graphServicePrincipal = Invoke-GraphRestRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'" -TenantId $TenantId
if (@($graphServicePrincipal.value).Count -ne 1 -or
    ($graphServicePrincipal.PSObject.Properties['@odata.nextLink'] -and $graphServicePrincipal.'@odata.nextLink')) {
  throw 'Exactly one Microsoft Graph service principal must be returned in the selected tenant.'
}

$resourceServicePrincipal = $graphServicePrincipal.value[0]
if ($resourceServicePrincipal.appId -ne '00000003-0000-0000-c000-000000000000') {
  throw 'The returned service principal is not Microsoft Graph.'
}
$appRoles = @($resourceServicePrincipal.appRoles | Where-Object { $_.value -and $_.isEnabled -and $_.allowedMemberTypes -contains 'Application' })
$existingAssignmentList = @(Get-MaesterGraphAssignmentList -TenantId $TenantId -PrincipalObjectId $PrincipalObjectId)

# Validate the complete requested role set before making the first assignment.
$requestedRoles = @(
  foreach ($appRoleValue in @($AppRoleValues | Select-Object -Unique)) {
    $match = @($appRoles | Where-Object { $_.value -eq $appRoleValue })
    if ($match.Count -ne 1) {
      throw "Exactly one enabled application role '$appRoleValue' must exist on Microsoft Graph."
    }
    $match[0]
  }
)
$createdAssignment = $false
foreach ($role in $requestedRoles) {
  $alreadyAssigned = @($existingAssignmentList | Where-Object {
    $_.principalId -eq $PrincipalObjectId -and $_.resourceId -eq $resourceServicePrincipal.id -and $_.appRoleId -eq $role.id
  })
  if ($alreadyAssigned.Count -gt 0) {
    Write-Host "App role '$($role.value)' already assigned."
    continue
  }

  $body = @{
    principalId = $PrincipalObjectId
    resourceId  = $resourceServicePrincipal.id
    appRoleId   = $role.id
  } | ConvertTo-Json

  Invoke-GraphRestRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalObjectId/appRoleAssignments" -Body $body -ContentType 'application/json' -TenantId $TenantId | Out-Null
  $createdAssignment = $true
}

# Read back exact principal/resource/role tuples before reporting completion.
# A short, read-only retry permits normal directory propagation after creation.
if ($createdAssignment) {
  for ($attempt = 1; $attempt -le 3; $attempt++) {
    $observedAssignments = @(Get-MaesterGraphAssignmentList -TenantId $TenantId -PrincipalObjectId $PrincipalObjectId)
    $missingRoles = @($requestedRoles | Where-Object {
      $roleId = $_.id
      -not @($observedAssignments | Where-Object {
        $_.principalId -eq $PrincipalObjectId -and $_.resourceId -eq $resourceServicePrincipal.id -and $_.appRoleId -eq $roleId
      }).Count
    })
    if ($missingRoles.Count -eq 0) { break }
    if ($attempt -lt 3) { Start-Sleep -Seconds 2 }
  }
  if ($missingRoles.Count -gt 0) {
    throw "Graph assignments could not be verified for: $($missingRoles.value -join ', '). Rerun after directory propagation; existing grants will be preserved."
  }
}

Write-Host 'Graph app role assignment completed.'
