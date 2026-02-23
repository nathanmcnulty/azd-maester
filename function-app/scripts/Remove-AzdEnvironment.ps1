[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$EnvironmentName,

  [Parameter(Mandatory = $false)]
  [switch]$KeepEnvironment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot/shared/Maester-Helpers.psm1" -Force

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot

Write-Host "Selecting azd environment '$EnvironmentName'"
& azd env select $EnvironmentName
if ($LASTEXITCODE -ne 0) {
  throw "Failed to select azd environment '$EnvironmentName'."
}

$resourceGroupName = $null
$subscriptionId = $null
$easyAuthAppObjectId = $null
$easyAuthAppClientId = $null
$functionAppMiPrincipalId = $null
$teamsRoleAssignmentIdsJson = $null
$azureRoleAssignmentIdsJson = $null
$exoAppRoleAssignmentIdsJson = $null
$exoServicePrincipalDisplayName = $null
$envValues = & azd env get-values
if ($LASTEXITCODE -eq 0) {
  $resourceGroupName = Get-EnvValue -Lines $envValues -Name 'AZURE_RESOURCE_GROUP'
  $subscriptionId = Get-EnvValue -Lines $envValues -Name 'AZURE_SUBSCRIPTION_ID'
  $easyAuthAppObjectId = Get-EnvValue -Lines $envValues -Name 'EASY_AUTH_ENTRA_APP_OBJECT_ID'
  $easyAuthAppClientId = Get-EnvValue -Lines $envValues -Name 'EASY_AUTH_ENTRA_APP_CLIENT_ID'
  $functionAppMiPrincipalId = Get-EnvValue -Lines $envValues -Name 'FUNCTION_APP_MI_PRINCIPAL_ID'
  $teamsRoleAssignmentIdsJson = Get-EnvValue -Lines $envValues -Name 'TEAMS_READER_ROLE_ASSIGNMENT_IDS'
  $azureRoleAssignmentIdsJson = Get-EnvValue -Lines $envValues -Name 'AZURE_ROLE_ASSIGNMENT_IDS'
  $exoAppRoleAssignmentIdsJson = Get-EnvValue -Lines $envValues -Name 'EXO_APPROLE_ASSIGNMENT_IDS'
  $exoServicePrincipalDisplayName = Get-EnvValue -Lines $envValues -Name 'EXO_SERVICE_PRINCIPAL_DISPLAY_NAME'
}

$teamsRoleAssignmentIds = ConvertFrom-JsonArrayOrEmpty -Json $teamsRoleAssignmentIdsJson
$azureRoleAssignmentIds = ConvertFrom-JsonArrayOrEmpty -Json $azureRoleAssignmentIdsJson
$exoAppRoleAssignmentIds = ConvertFrom-JsonArrayOrEmpty -Json $exoAppRoleAssignmentIdsJson

if (@($teamsRoleAssignmentIds).Count -gt 0) {
  Write-Host 'Removing Teams Reader Entra role assignments created by this environment...'
  foreach ($assignmentId in @($teamsRoleAssignmentIds)) {
    if ([string]::IsNullOrWhiteSpace($assignmentId)) {
      continue
    }

    & az rest --method delete --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/$assignmentId" | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Failed to remove Teams Reader role assignment id '$assignmentId'."
    }
  }
}


if (@($azureRoleAssignmentIds).Count -gt 0) {
  Write-Host 'Removing Azure RBAC role assignments created by this environment...'
  foreach ($roleAssignmentId in @($azureRoleAssignmentIds)) {
    if ([string]::IsNullOrWhiteSpace($roleAssignmentId)) {
      continue
    }

    & az role assignment delete --ids $roleAssignmentId | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Failed to remove Azure RBAC role assignment id '$roleAssignmentId'."
    }
  }
}

if (-not [string]::IsNullOrWhiteSpace($functionAppMiPrincipalId) -and @($exoAppRoleAssignmentIds).Count -gt 0) {
  Write-Host 'Removing Exchange appRoleAssignments created by this environment...'
  foreach ($assignmentId in @($exoAppRoleAssignmentIds)) {
    if ([string]::IsNullOrWhiteSpace($assignmentId)) {
      continue
    }

    & az rest --method delete --url "https://graph.microsoft.com/v1.0/servicePrincipals/$functionAppMiPrincipalId/appRoleAssignments/$assignmentId" | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Failed to remove Exchange appRoleAssignment id '$assignmentId'."
    }
  }
}

if (-not [string]::IsNullOrWhiteSpace($exoServicePrincipalDisplayName)) {
  Write-Host "Attempting Exchange RBAC cleanup for '$exoServicePrincipalDisplayName' (best-effort)..."
  try {
    if (Test-ModuleAvailable -ModuleName 'ExchangeOnlineManagement') {
      $exoToken = $null
      $exoOrganization = $null
      try {
        $exoToken = (az account get-access-token --resource https://outlook.office365.com --query accessToken -o tsv 2>$null)
        if ($exoToken) {
          $domainsJson = az rest --method get --url 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains' 2>$null
          if ($domainsJson) {
            $orgData = $domainsJson | ConvertFrom-Json
            if ($orgData.value -and $orgData.value.Count -gt 0) {
              $initialDomain = @($orgData.value[0].verifiedDomains | Where-Object { $_.isInitial -eq $true }) | Select-Object -First 1
              if ($initialDomain) {
                $exoOrganization = $initialDomain.name
              }
            }
          }
        }
      }
      catch { }
      if ($exoToken -and $exoOrganization) {
        Connect-ExchangeOnline -AccessToken $exoToken -Organization $exoOrganization -ShowBanner:$false | Out-Null
      }
      elseif ($exoToken) {
        Connect-ExchangeOnline -AccessToken $exoToken -ShowBanner:$false | Out-Null
      }
      else {
        Connect-ExchangeOnline -ShowBanner:$false -DisableWAM:$true | Out-Null
      }
      try {
        $assignments = Get-ManagementRoleAssignment -RoleAssignee $exoServicePrincipalDisplayName -ErrorAction SilentlyContinue
        foreach ($assignment in @($assignments)) {
          if ($assignment.Role -ne 'View-Only Configuration') {
            continue
          }
          Remove-ManagementRoleAssignment -Identity $assignment.Identity -Confirm:$false -ErrorAction SilentlyContinue
        }
      }
      catch {
        Write-Warning ("Failed to remove Exchange management role assignments. Error: {0}" -f $_.Exception.Message)
      }

      try {
        Remove-ServicePrincipal -Identity $exoServicePrincipalDisplayName -Confirm:$false -ErrorAction SilentlyContinue
      }
      catch {
      }
    }
    else {
      Write-Warning 'ExchangeOnlineManagement module is not available. Skipping Exchange RBAC cleanup.'
    }
  }
  catch {
    Write-Warning ("Exchange RBAC cleanup encountered an error. Skipping. Error: {0}" -f $_.Exception.Message)
  }
}

if (-not [string]::IsNullOrWhiteSpace($resourceGroupName)) {
  Remove-WebAppEasyAuthEntraApplications `
    -ResourceGroupName $resourceGroupName `
    -SubscriptionId $subscriptionId `
    -AdditionalApplicationObjectIds @($easyAuthAppObjectId) `
    -AdditionalClientIds @($easyAuthAppClientId)

  Write-Host "Removing resource locks in '$resourceGroupName' (if any)..."
  # Use ARM REST API to list all locks including resource-scoped ones (az lock list only returns group-level locks)
  $subscriptionParam = if (-not [string]::IsNullOrWhiteSpace($subscriptionId)) { @('--subscription', $subscriptionId) } else { @() }
  $locksUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Authorization/locks?api-version=2016-09-01"
  $locksRaw = & az rest --method get --url $locksUrl @subscriptionParam 2>$null
  if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($locksRaw)) {
    try {
      $locksPayload = $locksRaw | ConvertFrom-Json
      $lockIds = @($locksPayload.value | ForEach-Object { $_.id } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
      foreach ($lockId in $lockIds) {
        Write-Host "  Removing lock: $($lockId.Split('/')[-1])"
        & az lock delete --ids $lockId | Out-Null
        if ($LASTEXITCODE -ne 0) {
          Write-Warning "Failed to remove lock: $lockId"
        }
      }
      if ($lockIds.Count -gt 0) {
        Write-Host "  Waiting for lock deletions to propagate..."
        Start-Sleep -Seconds 15
      }
    }
    catch {
      Write-Warning "Failed to parse lock list response."
    }
  }
}

$azdDownMaxRetries = 3
$azdDownAttempt = 0
$azdDownSuccess = $false
while ($azdDownAttempt -lt $azdDownMaxRetries -and -not $azdDownSuccess) {
  $azdDownAttempt++
  if ($KeepEnvironment) {
    Write-Host 'Running azd down and keeping local environment files.'
    & azd down --force --no-prompt
  }
  else {
    Write-Host 'Running azd down and purging local environment files.'
    & azd down --force --purge --no-prompt
  }

  if ($LASTEXITCODE -eq 0) {
    $azdDownSuccess = $true
  }
  elseif ($azdDownAttempt -lt $azdDownMaxRetries) {
    Write-Warning "azd down attempt $azdDownAttempt failed (may be waiting for lock propagation). Retrying in 30 seconds..."
    Start-Sleep -Seconds 30
  }
}

if (-not $azdDownSuccess) {
  throw 'azd down failed after multiple attempts.'
}

if (-not $KeepEnvironment) {
  try {
    $localEnvPath = Join-Path -Path (Join-Path $projectRoot '.azure') -ChildPath $EnvironmentName
    if (Test-Path -Path $localEnvPath) {
      Remove-Item -Path $localEnvPath -Recurse -Force -ErrorAction Stop
      Write-Host "Removed local azd environment folder: $localEnvPath"
    }
  }
  catch {
    Write-Warning "Failed to remove local azd environment folder for '$EnvironmentName'. Error: $($_.Exception.Message)"
  }
}

if ($KeepEnvironment) {
  Write-Host 'Clearing Easy Auth Entra app metadata from kept azd environment...'
  Clear-AzdEnvironmentValue -Name 'EASY_AUTH_ENTRA_APP_OBJECT_ID'
  Clear-AzdEnvironmentValue -Name 'EASY_AUTH_ENTRA_APP_CLIENT_ID'
  Clear-AzdEnvironmentValue -Name 'EASY_AUTH_ENTRA_APP_DISPLAY_NAME'

  Write-Host 'Clearing advanced include and assignment metadata from kept azd environment...'
  Clear-AzdEnvironmentValue -Name 'INCLUDE_EXCHANGE'
  Clear-AzdEnvironmentValue -Name 'INCLUDE_TEAMS'
  Clear-AzdEnvironmentValue -Name 'INCLUDE_AZURE'
  Clear-AzdEnvironmentValue -Name 'AZURE_RBAC_SCOPES'
  Clear-AzdEnvironmentValue -Name 'SETUP_EXCHANGE_STATUS'
  Clear-AzdEnvironmentValue -Name 'SETUP_TEAMS_STATUS'
  Clear-AzdEnvironmentValue -Name 'SETUP_AZURE_STATUS'
  Clear-AzdEnvironmentValue -Name 'EXO_APPROLE_ASSIGNMENT_IDS'
  Clear-AzdEnvironmentValue -Name 'TEAMS_READER_ROLE_ASSIGNMENT_IDS'
  Clear-AzdEnvironmentValue -Name 'AZURE_ROLE_ASSIGNMENT_IDS'
  Clear-AzdEnvironmentValue -Name 'EXO_SERVICE_PRINCIPAL_DISPLAY_NAME'
  Clear-AzdEnvironmentValue -Name 'FUNCTION_APP_MI_PRINCIPAL_ID'
}

Write-Host "Environment removal completed for '$EnvironmentName'."
