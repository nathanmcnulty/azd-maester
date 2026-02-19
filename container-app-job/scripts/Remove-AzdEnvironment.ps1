[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$EnvironmentName,

  [Parameter(Mandatory = $false)]
  [switch]$KeepEnvironment
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

function Clear-AzdEnvironmentValue {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  & azd env set "$Name="
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "Failed to clear azd environment value '$Name'."
    return
  }

  Write-Host "Cleared azd environment value '$Name'."
}

function Test-CanPrompt {
  try {
    $null = $Host.UI.RawUI
    return $true
  }
  catch {
    return $false
  }
}

function ConvertFrom-JsonArrayOrEmpty {
  param(
    [Parameter(Mandatory = $false)]
    [string]$Json
  )

  if ([string]::IsNullOrWhiteSpace($Json)) {
    return @()
  }

  $text = $Json.Trim()
  if (-not $text.StartsWith('[')) {
    return @($text -split ';' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  }

  try {
    $parsed = $text | ConvertFrom-Json
    if (-not $parsed) {
      return @()
    }

    if ($parsed -is [string]) {
      return @($parsed)
    }

    return @($parsed)
  }
  catch {
    Write-Warning "Failed to parse JSON array value. Skipping. Value: $Json"
    return @()
  }
}

function Test-ModuleAvailable {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ModuleName
  )

  $available = Get-Module -ListAvailable -Name $ModuleName | Select-Object -First 1
  if ($available) {
    Import-Module $ModuleName -Force
    return $true
  }

  if (-not (Test-CanPrompt)) {
    Write-Warning "$ModuleName is not installed and this is a non-interactive session."
    return $false
  }

  $installChoice = Read-Host "Install PowerShell module '$ModuleName' now? (Y/N)"
  if (-not $installChoice -or $installChoice.Trim().ToUpper() -ne 'Y') {
    return $false
  }

  Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
  Import-Module $ModuleName -Force
  return $true
}

function Remove-WebAppEasyAuthEntraApplications {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string[]]$AdditionalApplicationObjectIds,

    [Parameter(Mandatory = $false)]
    [string[]]$AdditionalClientIds
  )

  $applicationObjectIds = New-Object System.Collections.Generic.HashSet[string]
  $clientIds = New-Object System.Collections.Generic.HashSet[string]

  foreach ($additionalObjectId in @($AdditionalApplicationObjectIds)) {
    if (-not [string]::IsNullOrWhiteSpace($additionalObjectId)) {
      [void]$applicationObjectIds.Add($additionalObjectId)
    }
  }

  foreach ($additionalClientId in @($AdditionalClientIds)) {
    if (-not [string]::IsNullOrWhiteSpace($additionalClientId)) {
      [void]$clientIds.Add($additionalClientId)
    }
  }

  $subscriptionArgs = @()
  if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
    $subscriptionArgs = @('--subscription', $SubscriptionId)
  }

  if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
    Write-Host "Discovering Web Apps in '$ResourceGroupName' for Easy Auth Entra app cleanup..."
    $webAppNamesRaw = & az resource list --resource-group $ResourceGroupName --resource-type Microsoft.Web/sites --query '[].name' -o tsv @subscriptionArgs
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Unable to list Web Apps in '$ResourceGroupName'. Continuing with env-based Easy Auth app cleanup only."
    }
    else {
      $webAppNames = @($webAppNamesRaw -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
      foreach ($webAppName in $webAppNames) {
        $authSettingsUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$webAppName/config/authsettingsV2?api-version=2023-12-01"
        $authRaw = & az rest --method get --url $authSettingsUrl @subscriptionArgs
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($authRaw)) {
          continue
        }

        try {
          $auth = $authRaw | ConvertFrom-Json
          $clientId = $auth.properties.identityProviders.azureActiveDirectory.registration.clientId
          if (-not [string]::IsNullOrWhiteSpace($clientId)) {
            [void]$clientIds.Add($clientId)
          }
        }
        catch {
          Write-Warning "Failed to parse authsettingsV2 for Web App '$webAppName'. Skipping."
        }
      }
    }
  }
  else {
    Write-Warning 'AZURE_SUBSCRIPTION_ID is not set. Skipping Web App authsettings discovery and using env-based Easy Auth app cleanup only.'
  }

  $deletedAppObjectIds = New-Object System.Collections.Generic.HashSet[string]
  foreach ($appObjectId in $applicationObjectIds) {
    $applicationRaw = & az rest --method get --url "https://graph.microsoft.com/v1.0/applications/${appObjectId}?`$select=id,appId,displayName"
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($applicationRaw)) {
      Write-Warning "Unable to query Entra application by objectId '$appObjectId'."
      continue
    }

    try {
      $application = $applicationRaw | ConvertFrom-Json
    }
    catch {
      Write-Warning "Failed to parse Entra application lookup for objectId '$appObjectId'."
      continue
    }

    $displayName = if ($application.displayName) { $application.displayName } else { '' }
    if ($displayName -notlike 'maester-easyauth-*') {
      Write-Warning "Skipping Entra application '$displayName' ($($application.id)) because it does not match the expected Easy Auth naming convention."
      continue
    }

    Write-Host "Removing Easy Auth Entra application '$displayName' ($($application.appId))"
    & az rest --method delete --url "https://graph.microsoft.com/v1.0/applications/$($application.id)" | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Failed to remove Entra application '$displayName' ($($application.id))."
      continue
    }

    [void]$deletedAppObjectIds.Add($application.id)
  }

  foreach ($clientId in $clientIds) {
    $appByClientIdRaw = & az ad app show --id $clientId -o json 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($appByClientIdRaw)) {
      continue
    }

    try {
      $appByClientId = $appByClientIdRaw | ConvertFrom-Json
      $apps = @($appByClientId)
    }
    catch {
      Write-Warning "Failed to parse Entra application lookup for appId '$clientId'."
      continue
    }

    if (-not $apps -or $apps.Count -eq 0) {
      continue
    }

    foreach ($app in @($apps)) {
      if ($deletedAppObjectIds.Contains($app.id)) {
        continue
      }

      $displayName = if ($app.displayName) { $app.displayName } else { '' }
      if ($displayName -notlike 'maester-easyauth-*') {
        Write-Warning "Skipping Entra application '$displayName' ($($app.id)) because it does not match the expected Easy Auth naming convention."
        continue
      }

      Write-Host "Removing Easy Auth Entra application '$displayName' ($($app.appId))"
      & az rest --method delete --url "https://graph.microsoft.com/v1.0/applications/$($app.id)" | Out-Null
      if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to remove Entra application '$displayName' ($($app.id))."
        continue
      }

      [void]$deletedAppObjectIds.Add($app.id)
    }
  }
}

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
$containerJobMiPrincipalId = $null
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
  $containerJobMiPrincipalId = Get-EnvValue -Lines $envValues -Name 'CONTAINER_JOB_MI_PRINCIPAL_ID'
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

if (-not [string]::IsNullOrWhiteSpace($containerJobMiPrincipalId) -and @($exoAppRoleAssignmentIds).Count -gt 0) {
  Write-Host 'Removing Exchange appRoleAssignments created by this environment...'
  foreach ($assignmentId in @($exoAppRoleAssignmentIds)) {
    if ([string]::IsNullOrWhiteSpace($assignmentId)) {
      continue
    }

    & az rest --method delete --url "https://graph.microsoft.com/v1.0/servicePrincipals/$containerJobMiPrincipalId/appRoleAssignments/$assignmentId" | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Failed to remove Exchange appRoleAssignment id '$assignmentId'."
    }
  }
}

if (-not [string]::IsNullOrWhiteSpace($exoServicePrincipalDisplayName)) {
  Write-Host "Attempting Exchange RBAC cleanup for '$exoServicePrincipalDisplayName' (best-effort)..."
  try {
    if (Test-ModuleAvailable -ModuleName 'ExchangeOnlineManagement') {
      # Use az CLI token to avoid interactive login prompts
      $exoToken = $null
      $exoOrganization = $null
      try {
        $exoToken = (az account get-access-token --resource https://outlook.office365.com --query accessToken -o tsv 2>$null)
        if ($exoToken) {
          # Resolve tenant initial domain required by Connect-ExchangeOnline with AccessToken
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
  $lockIdsRaw = & az lock list --resource-group $resourceGroupName --query '[].id' -o tsv
  if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($lockIdsRaw)) {
    $lockIds = @($lockIdsRaw -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    foreach ($lockId in $lockIds) {
      & az lock delete --ids $lockId | Out-Null
    }
  }
}

if ($KeepEnvironment) {
  Write-Host 'Running azd down and keeping local environment files.'
  & azd down --force --no-prompt
}
else {
  Write-Host 'Running azd down and purging local environment files.'
  & azd down --force --purge --no-prompt
}

if ($LASTEXITCODE -ne 0) {
  throw 'azd down failed.'
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
  Clear-AzdEnvironmentValue -Name 'INCLUDE_ACR'
  Clear-AzdEnvironmentValue -Name 'AZURE_RBAC_SCOPES'
  Clear-AzdEnvironmentValue -Name 'SETUP_EXCHANGE_STATUS'
  Clear-AzdEnvironmentValue -Name 'SETUP_TEAMS_STATUS'
  Clear-AzdEnvironmentValue -Name 'SETUP_AZURE_STATUS'
  Clear-AzdEnvironmentValue -Name 'EXO_APPROLE_ASSIGNMENT_IDS'
  Clear-AzdEnvironmentValue -Name 'TEAMS_READER_ROLE_ASSIGNMENT_IDS'
  Clear-AzdEnvironmentValue -Name 'AZURE_ROLE_ASSIGNMENT_IDS'
  Clear-AzdEnvironmentValue -Name 'EXO_SERVICE_PRINCIPAL_DISPLAY_NAME'
  Clear-AzdEnvironmentValue -Name 'CONTAINER_JOB_MI_PRINCIPAL_ID'
}

Write-Host "Environment removal completed for '$EnvironmentName'."
