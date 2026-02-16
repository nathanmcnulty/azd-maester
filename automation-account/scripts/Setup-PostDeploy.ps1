[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$EnvironmentName,

  [Parameter(Mandatory = $false)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $false)]
  [string]$TenantId,

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

Import-Module Az.Accounts -Force
Import-Module Microsoft.Graph.Authentication -Force

if (-not $SubscriptionId) {
  $SubscriptionId = $env:AZURE_SUBSCRIPTION_ID
}
if (-not $SubscriptionId) {
  throw 'SubscriptionId is required. Pass -SubscriptionId or set AZURE_SUBSCRIPTION_ID.'
}

if (-not $TenantId -and $env:AZURE_TENANT_ID) {
  $TenantId = $env:AZURE_TENANT_ID
}

$existingContext = Get-AzContext -ErrorAction SilentlyContinue
$requiresLogin = $true
if ($existingContext -and $existingContext.Subscription -and $existingContext.Subscription.Id -eq $SubscriptionId) {
  if (-not $TenantId -or ($existingContext.Tenant -and $existingContext.Tenant.Id -eq $TenantId)) {
    $requiresLogin = $false
  }
}

if ($requiresLogin) {
  $connectParameters = @{ Subscription = $SubscriptionId }
  if ($TenantId) {
    $connectParameters['Tenant'] = $TenantId
  }
  Connect-AzAccount @connectParameters | Out-Null
}

$context = Get-AzContext
if (-not $SubscriptionId) {
  $SubscriptionId = $context.Subscription.Id
}
if (-not $TenantId -and $context.Tenant) {
  $TenantId = $context.Tenant.Id
}
if (-not $EnvironmentName) {
  $EnvironmentName = if ($env:AZURE_ENV_NAME) { $env:AZURE_ENV_NAME } else { 'dev' }
}
if (-not $PSBoundParameters.ContainsKey('PermissionProfile') -and $env:PERMISSION_PROFILE) {
  $envPermissionProfile = $env:PERMISSION_PROFILE.Trim()
  if ($envPermissionProfile -notin @('Minimal', 'Extended')) {
    throw "PERMISSION_PROFILE must be 'Minimal' or 'Extended'. Current value: '$envPermissionProfile'."
  }
  $PermissionProfile = $envPermissionProfile
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

$securityGroupSource = 'parameter'
if (-not $PSBoundParameters.ContainsKey('SecurityGroupObjectId') -and -not $PSBoundParameters.ContainsKey('SecurityGroupDisplayName')) {
  if ($env:SECURITY_GROUP_OBJECT_ID -or $env:EASY_AUTH_SECURITY_GROUP_OBJECT_ID) {
    $securityGroupSource = 'environment'
  }
}

$resolvedResourceGroupName = if ($ResourceGroupName) { $ResourceGroupName } elseif ($env:AZURE_RESOURCE_GROUP) { $env:AZURE_RESOURCE_GROUP } else { "rg-$EnvironmentName" }

$storageQuery = "/subscriptions/$SubscriptionId/resourceGroups/$resolvedResourceGroupName/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01"
$storageResponse = Invoke-AzRestMethod -Method GET -Path $storageQuery
$storagePayload = $storageResponse.Content | ConvertFrom-Json
if (-not $storagePayload.value -or $storagePayload.value.Count -eq 0) {
  throw "No Storage Account resources were found in resource group '$resolvedResourceGroupName'."
}

$preferredStorageAccountName = "stmaester$($EnvironmentName.ToLower())"
$storageAccount = @($storagePayload.value | Where-Object { $_.name -eq $preferredStorageAccountName }) | Select-Object -First 1
if (-not $storageAccount) {
  $storageAccount = @($storagePayload.value | Where-Object { $_.name -like 'stmaester*' }) | Select-Object -First 1
}
if (-not $storageAccount) {
  $storageAccount = $storagePayload.value[0]
}

$storageBlobDataReaderRoleId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"

$signedInUser = $null
try {
  Connect-MgGraph -TenantId $TenantId -Scopes 'User.Read','Directory.Read.All' -NoWelcome | Out-Null
  $signedInUser = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,displayName'
}
catch {
  Write-Warning ("Could not resolve signed-in Entra user from Microsoft Graph for Storage Blob Data Reader assignment. Error: {0}" -f $_.Exception.Message)
}

if (-not $signedInUser -or -not $signedInUser.id) {
  try {
    $signedInUserJson = az ad signed-in-user show --query "{id:id,userPrincipalName:userPrincipalName,displayName:displayName}" -o json 2>$null
    if ($LASTEXITCODE -eq 0 -and $signedInUserJson) {
      $signedInUser = $signedInUserJson | ConvertFrom-Json
      Write-Host 'Resolved signed-in user via Azure CLI fallback.'
    }
  }
  catch {
    Write-Warning ("Could not resolve signed-in Entra user from Azure CLI fallback. Error: {0}" -f $_.Exception.Message)
  }
}

if ($signedInUser -and $signedInUser.id) {
  $existingReaderAssignmentsPath = "$($storageAccount.id)/providers/Microsoft.Authorization/roleAssignments?`$filter=atScope()&api-version=2022-04-01"
  $existingReaderAssignmentsResponse = Invoke-AzRestMethod -Method GET -Path $existingReaderAssignmentsPath
  $existingReaderAssignments = ($existingReaderAssignmentsResponse.Content | ConvertFrom-Json).value
  $existingReaderAssignment = @($existingReaderAssignments | Where-Object {
      $_.properties.principalId -eq $signedInUser.id -and $_.properties.roleDefinitionId -eq $storageBlobDataReaderRoleId
    }) | Select-Object -First 1

  if (-not $existingReaderAssignment) {
    $readerAssignmentName = [guid]::NewGuid().ToString()
    $readerAssignmentPath = "$($storageAccount.id)/providers/Microsoft.Authorization/roleAssignments/${readerAssignmentName}?api-version=2022-04-01"
    $readerAssignmentBody = @{
      properties = @{
        roleDefinitionId = $storageBlobDataReaderRoleId
        principalId = $signedInUser.id
        principalType = 'User'
      }
    } | ConvertTo-Json -Depth 10

    Invoke-AzRestMethod -Method PUT -Path $readerAssignmentPath -Payload $readerAssignmentBody | Out-Null
  }

  $userLabel = if ($signedInUser.userPrincipalName) { $signedInUser.userPrincipalName } else { $signedInUser.id }
  Write-Host "Granted Storage Blob Data Reader on '$($storageAccount.name)' to signed-in user '$userLabel'."
}
else {
  Write-Warning 'Signed-in user object id was not available. Storage Blob Data Reader assignment for user was skipped.'
}

$automationQuery = "/subscriptions/$SubscriptionId/resourceGroups/$resolvedResourceGroupName/providers/Microsoft.Automation/automationAccounts?api-version=2023-11-01"
$automationResponse = Invoke-AzRestMethod -Method GET -Path $automationQuery
$automationPayload = $automationResponse.Content | ConvertFrom-Json
if (-not $automationPayload.value -or $automationPayload.value.Count -eq 0) {
  throw "No Automation Account resources were found in resource group '$resolvedResourceGroupName'."
}

$preferredAutomationAccountName = "aa-$($EnvironmentName.ToLower())"
$automationAccount = @($automationPayload.value | Where-Object { $_.name -eq $preferredAutomationAccountName }) | Select-Object -First 1
if (-not $automationAccount) {
  $automationAccount = $automationPayload.value[0]
}

$automationAccountName = $automationAccount.name

$principalId = & "$PSScriptRoot\Get-ManagedIdentityPrincipal.ps1" `
  -SubscriptionId $SubscriptionId `
  -ResourceGroupName $resolvedResourceGroupName `
  -ProviderNamespace 'Microsoft.Automation' `
  -ResourceType 'automationAccounts' `
  -ResourceName $automationAccountName `
  -ApiVersion '2023-11-01'

& "$PSScriptRoot\Grant-MaesterGraphPermissions.ps1" `
  -TenantId $TenantId `
  -PrincipalObjectId $principalId `
  -PermissionProfile $PermissionProfile

Write-Host "Automation account '$automationAccountName' managed identity is configured for Maester Graph permissions."

$runbookContentPath = Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-MaesterAutomationRunbook.ps1'
if (-not (Test-Path -Path $runbookContentPath)) {
  throw "Runbook content file was not found: $runbookContentPath"
}

$runbookName = 'maester-runbook'
$runbookContent = Get-Content -Path $runbookContentPath -Raw
$armApiVersion = '2024-10-23'

$draftUri = "/subscriptions/$SubscriptionId/resourceGroups/$resolvedResourceGroupName/providers/Microsoft.Automation/automationAccounts/$automationAccountName/runbooks/$runbookName/draft/content?api-version=$armApiVersion"
Invoke-AzRestMethod -Method PUT -Path $draftUri -Payload $runbookContent | Out-Null
Write-Host "Uploaded draft content for runbook '$runbookName'."

$publishUri = "/subscriptions/$SubscriptionId/resourceGroups/$resolvedResourceGroupName/providers/Microsoft.Automation/automationAccounts/$automationAccountName/runbooks/$runbookName/publish?api-version=$armApiVersion"
Invoke-AzRestMethod -Method POST -Path $publishUri -Payload '{}' | Out-Null
Write-Host "Published runbook '$runbookName' with local script content."

$webAppsQuery = "/subscriptions/$SubscriptionId/resourceGroups/$resolvedResourceGroupName/providers/Microsoft.Web/sites?api-version=2023-12-01"
$webAppsResponse = Invoke-AzRestMethod -Method GET -Path $webAppsQuery
$webAppsPayload = $webAppsResponse.Content | ConvertFrom-Json

if ($webAppsPayload.value -and $webAppsPayload.value.Count -gt 0) {
  if (-not $SecurityGroupObjectId -and -not [string]::IsNullOrWhiteSpace($SecurityGroupDisplayName)) {
    Connect-MgGraph -TenantId $TenantId -Scopes 'Group.Read.All','Directory.Read.All' -NoWelcome | Out-Null

    $escapedDisplayName = [System.Uri]::EscapeDataString("'$SecurityGroupDisplayName'")
    $groupsResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq $escapedDisplayName&`$select=id,displayName,description&`$top=25"
    $groupMatches = @($groupsResponse.value)

    if ($groupMatches.Count -eq 0) {
      throw "No Entra security groups found with display name '$SecurityGroupDisplayName'."
    }

    if ($groupMatches.Count -eq 1) {
      $SecurityGroupObjectId = $groupMatches[0].id
      Write-Host "Resolved security group '$SecurityGroupDisplayName' to object ID '$SecurityGroupObjectId'."
    }
    else {
      $canPrompt = $false
      try {
        $null = $Host.UI.RawUI
        $canPrompt = $true
      }
      catch {
        $canPrompt = $false
      }

      if (-not $canPrompt) {
        throw "Multiple Entra security groups matched '$SecurityGroupDisplayName'. Provide SecurityGroupObjectId to avoid ambiguity."
      }

      Write-Host "Multiple groups matched '$SecurityGroupDisplayName'. Select one:"
      for ($index = 0; $index -lt $groupMatches.Count; $index++) {
        $item = $groupMatches[$index]
        $description = if ($item.description) { $item.description } else { 'n/a' }
        Write-Host ("[{0}] {1} ({2})" -f ($index + 1), $item.displayName, $description)
      }

      $selection = Read-Host 'Enter selection number'
      $selectionValue = 0
      if (-not [int]::TryParse($selection, [ref]$selectionValue)) {
        throw 'Selection was not a valid number.'
      }

      $selectionIndex = $selectionValue - 1
      if ($selectionIndex -lt 0 -or $selectionIndex -ge $groupMatches.Count) {
        throw 'Selection is out of range.'
      }

      $SecurityGroupObjectId = $groupMatches[$selectionIndex].id
      Write-Host "Selected security group object ID: $SecurityGroupObjectId"
    }
  }

  if (-not $SecurityGroupObjectId) {
    $canPrompt = $false
    try {
      $null = $Host.UI.RawUI
      $canPrompt = $true
    }
    catch {
      $canPrompt = $false
    }

    if ($canPrompt) {
      $SecurityGroupObjectId = Read-Host "Optional Web App detected. Enter Entra security group object ID to allow access via Easy Auth"
      $securityGroupSource = 'interactive-prompt'
    }
  }

  if (-not $SecurityGroupObjectId) {
    throw 'SecurityGroupObjectId is required to configure Easy Auth when includeWebApp=true. Provide -SecurityGroupObjectId, set SECURITY_GROUP_OBJECT_ID, or set EASY_AUTH_SECURITY_GROUP_OBJECT_ID.'
  }

  Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All','Directory.Read.All','DelegatedPermissionGrant.ReadWrite.All' -NoWelcome | Out-Null

  $preferredWebAppName = "app-maester-$($EnvironmentName.ToLower())"
  $webApp = @($webAppsPayload.value | Where-Object { $_.name -eq $preferredWebAppName }) | Select-Object -First 1
  if (-not $webApp) {
    $webApp = $webAppsPayload.value[0]
  }

  $webAppName = $webApp.name
  $webAppHostName = $webApp.properties.defaultHostName
  $redirectUri = "https://$webAppHostName/.auth/login/aad/callback"
  $easyAuthDisplayName = "maester-easyauth-$webAppName"

  $encodedDisplayName = [System.Uri]::EscapeDataString("'$easyAuthDisplayName'")
  $existingAppResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq $encodedDisplayName"
  $desiredRedirectUris = @($redirectUri)
  $aadApp = if ($existingAppResponse.value -and $existingAppResponse.value.Count -gt 0) {
    $existingApp = $existingAppResponse.value[0]

    $existingRedirectUris = @()
    if ($existingApp.web -and $existingApp.web.redirectUris) {
      $existingRedirectUris = @($existingApp.web.redirectUris)
    }

    $mergedRedirectUris = @($existingRedirectUris + $desiredRedirectUris | Sort-Object -Unique)
    $updateAppBody = @{
      groupMembershipClaims = 'SecurityGroup'
      web = @{
        redirectUris = $mergedRedirectUris
        implicitGrantSettings = @{
          enableIdTokenIssuance = $true
          enableAccessTokenIssuance = $false
        }
      }
    } | ConvertTo-Json -Depth 10

    Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($existingApp.id)" -Body $updateAppBody -ContentType 'application/json' | Out-Null
    Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications/$($existingApp.id)?`$select=id,appId,displayName,groupMembershipClaims,web"
  }
  else {
    $createAppBody = @{
      displayName = $easyAuthDisplayName
      signInAudience = 'AzureADMyOrg'
      groupMembershipClaims = 'SecurityGroup'
      web = @{
        redirectUris = $desiredRedirectUris
        implicitGrantSettings = @{
          enableIdTokenIssuance = $true
          enableAccessTokenIssuance = $false
        }
      }
    } | ConvertTo-Json -Depth 10
    Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body $createAppBody -ContentType 'application/json'
  }

  Write-Host "Persisting Easy Auth Entra app identifiers to azd environment variables..."
  & azd env set EASY_AUTH_ENTRA_APP_OBJECT_ID $aadApp.id
  if ($LASTEXITCODE -ne 0) {
    Write-Warning 'Failed to persist EASY_AUTH_ENTRA_APP_OBJECT_ID to azd environment.'
  }

  & azd env set EASY_AUTH_ENTRA_APP_CLIENT_ID $aadApp.appId
  if ($LASTEXITCODE -ne 0) {
    Write-Warning 'Failed to persist EASY_AUTH_ENTRA_APP_CLIENT_ID to azd environment.'
  }

  & azd env set EASY_AUTH_ENTRA_APP_DISPLAY_NAME $aadApp.displayName
  if ($LASTEXITCODE -ne 0) {
    Write-Warning 'Failed to persist EASY_AUTH_ENTRA_APP_DISPLAY_NAME to azd environment.'
  }

  $servicePrincipalResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$($aadApp.appId)'"
  $easyAuthServicePrincipal = $null
  if (-not $servicePrincipalResponse.value -or $servicePrincipalResponse.value.Count -eq 0) {
    $spBody = @{ appId = $aadApp.appId } | ConvertTo-Json
    $easyAuthServicePrincipal = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Body $spBody -ContentType 'application/json'
  }
  else {
    $easyAuthServicePrincipal = $servicePrincipalResponse.value[0]
  }

  $graphSpResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id"
  if (-not $graphSpResponse.value -or $graphSpResponse.value.Count -eq 0) {
    throw 'Microsoft Graph service principal was not found while configuring Easy Auth admin consent.'
  }

  $graphSpId = $graphSpResponse.value[0].id
  $consentScope = 'openid profile email User.Read'
  $existingGrantResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($easyAuthServicePrincipal.id)' and resourceId eq '$graphSpId' and consentType eq 'AllPrincipals'"
  if ($existingGrantResponse.value -and $existingGrantResponse.value.Count -gt 0) {
    $existingGrant = $existingGrantResponse.value[0]
    $currentScopes = @()
    if ($existingGrant.scope) {
      $currentScopes = @($existingGrant.scope -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    $requiredScopes = @($consentScope -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $mergedScopes = @($currentScopes + $requiredScopes | Sort-Object -Unique)
    $mergedScopeString = $mergedScopes -join ' '

    if ($mergedScopeString -ne $existingGrant.scope) {
      $patchGrantBody = @{ scope = $mergedScopeString } | ConvertTo-Json
      Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($existingGrant.id)" -Body $patchGrantBody -ContentType 'application/json' | Out-Null
    }
  }
  else {
    $grantBody = @{
      clientId = $easyAuthServicePrincipal.id
      consentType = 'AllPrincipals'
      resourceId = $graphSpId
      scope = $consentScope
    } | ConvertTo-Json

    Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -Body $grantBody -ContentType 'application/json' | Out-Null
  }

  $authPayload = @{
    properties = @{
      platform = @{
        enabled = $true
      }
      globalValidation = @{
        requireAuthentication = $true
        unauthenticatedClientAction = 'RedirectToLoginPage'
      }
      httpSettings = @{
        requireHttps = $true
      }
      identityProviders = @{
        azureActiveDirectory = @{
          enabled = $true
          registration = @{
            clientId = $aadApp.appId
            openIdIssuer = "https://login.microsoftonline.com/$TenantId/v2.0"
          }
          validation = @{
            allowedAudiences = @("https://$webAppHostName")
            defaultAuthorizationPolicy = @{
              allowedPrincipals = @{
                groups = @($SecurityGroupObjectId)
              }
            }
          }
        }
      }
      login = @{
        routes = @{}
      }
    }
  } | ConvertTo-Json -Depth 15

  $authPath = "/subscriptions/$SubscriptionId/resourceGroups/$resolvedResourceGroupName/providers/Microsoft.Web/sites/$webAppName/config/authsettingsV2?api-version=2023-12-01"
  Invoke-AzRestMethod -Method PUT -Path $authPath -Payload $authPayload | Out-Null

  Write-Host "Configured Easy Auth for Web App '$webAppName'."
  Write-Host "Easy Auth Entra app display name: $easyAuthDisplayName"
  Write-Host "Easy Auth Entra app objectId: $($aadApp.id)"
  Write-Host "Easy Auth Entra app clientId: $($aadApp.appId)"
  Write-Host "Easy Auth issuer: https://login.microsoftonline.com/$TenantId/v2.0"
  Write-Host "Easy Auth groupMembershipClaims: $($aadApp.groupMembershipClaims)"
  if ($aadApp.web -and $aadApp.web.implicitGrantSettings) {
    Write-Host "Easy Auth implicit id_token enabled: $($aadApp.web.implicitGrantSettings.enableIdTokenIssuance)"
  }
  Write-Host "Easy Auth admin consent scopes: $consentScope"
  Write-Host "Easy Auth security group: $SecurityGroupObjectId (source: $securityGroupSource)"
}
