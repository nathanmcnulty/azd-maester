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
  [string]$PermissionProfile = 'Extended',

  [Parameter(Mandatory = $false)]
  [switch]$IncludeExchange,

  [Parameter(Mandatory = $false)]
  [switch]$IncludeTeams,

  [Parameter(Mandatory = $false)]
  [switch]$IncludeAzure,

  [Parameter(Mandatory = $false)]
  [string[]]$AzureScopes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot

Import-Module Az.Accounts -Force
Import-Module Microsoft.Graph.Authentication -Force

function Test-CanPrompt {
  try {
    $null = $Host.UI.RawUI
    return $true
  }
  catch {
    return $false
  }
}

function ConvertTo-BoolOrDefault {
  param(
    [Parameter(Mandatory = $false)]
    [string]$Value,
    [Parameter(Mandatory = $true)]
    [bool]$Default
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return $Default
  }

  switch ($Value.Trim().ToLower()) {
    'true' { return $true }
    'false' { return $false }
    default { return $Default }
  }
}

function Resolve-StepFailureAction {
  param(
    [Parameter(Mandatory = $true)]
    [string]$StepName,
    [Parameter(Mandatory = $true)]
    [string]$Message
  )

  Write-Warning ("{0} failed: {1}" -f $StepName, $Message)

  if (-not (Test-CanPrompt)) {
    Write-Warning "Non-interactive session detected. Skipping $StepName and continuing."
    return 'Skip'
  }

  Write-Host "Choose how to proceed after failure in '$StepName':"
  Write-Host '  [S] Stop setup (recommended if you need the feature enabled)'
  Write-Host '  [K] Skip this step and continue'
  $choice = Read-Host 'Enter S or K (default: K)'
  if ($choice -and $choice.Trim().ToUpper() -eq 'S') {
    return 'Stop'
  }

  return 'Skip'
}

function Set-AzdEnvValue {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$Value
  )

  try {
    & azd env set $Name $Value | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Failed to persist $Name to azd environment."
    }
  }
  catch {
    Write-Warning "Failed to persist $Name to azd environment. Error: $($_.Exception.Message)"
  }
}

function Set-AzdEnvJsonArray {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [Parameter(Mandatory = $false)]
    [AllowEmptyCollection()]
    [string[]]$Values = @()
  )

  $serialized = (@($Values) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) -join ';'
  Set-AzdEnvValue -Name $Name -Value $serialized
}

function Ensure-ModuleAvailable {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ModuleName,
    [Parameter(Mandatory = $false)]
    [string]$InstallMessage
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

  if ($InstallMessage) {
    Write-Host $InstallMessage
  }

  $installChoice = Read-Host "Install PowerShell module '$ModuleName' now? (Y/N)"
  if (-not $installChoice -or $installChoice.Trim().ToUpper() -ne 'Y') {
    return $false
  }

  Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
  Import-Module $ModuleName -Force
  return $true
}

function Get-AzCliAccessToken {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Resource
  )

  try {
    $tokenJson = az account get-access-token --resource $Resource -o json 2>$null
    if ($LASTEXITCODE -eq 0 -and $tokenJson) {
      $tokenData = $tokenJson | ConvertFrom-Json
      if ($tokenData.accessToken) {
        return $tokenData.accessToken
      }
    }
  }
  catch {
    Write-Verbose "az cli token acquisition failed for ${Resource}: $($_.Exception.Message)"
  }

  return $null
}

function Connect-MgGraphSilent {
  param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    [Parameter(Mandatory = $false)]
    [string[]]$Scopes = @()
  )

  $token = Get-AzCliAccessToken -Resource 'https://graph.microsoft.com'
  if ($token) {
    $secureToken = ConvertTo-SecureString $token -AsPlainText -Force
    Connect-MgGraph -AccessToken $secureToken -NoWelcome | Out-Null
    return
  }

  Write-Verbose 'az cli token not available for Microsoft Graph. Falling back to interactive auth.'
  if ($Scopes.Count -gt 0) {
    Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome | Out-Null
  }
  else {
    Connect-MgGraph -TenantId $TenantId -Scopes 'User.Read' -NoWelcome | Out-Null
  }
}

function Connect-ExchangeOnlineSilent {
  param(
    [Parameter(Mandatory = $false)]
    [string]$Organization
  )

  $token = Get-AzCliAccessToken -Resource 'https://outlook.office365.com'
  if ($token) {
    $connectArgs = @{
      AccessToken = $token
      ShowBanner  = $false
    }
    if (-not [string]::IsNullOrWhiteSpace($Organization)) {
      $connectArgs['Organization'] = $Organization
    }
    Connect-ExchangeOnline @connectArgs | Out-Null
    return
  }

  Write-Verbose 'az cli token not available for Exchange Online. Falling back to interactive auth.'
  $connectArgs = @{
    ShowBanner = $false
    DisableWAM = $true
  }
  if (-not [string]::IsNullOrWhiteSpace($Organization)) {
    $connectArgs['Organization'] = $Organization
  }
  Connect-ExchangeOnline @connectArgs | Out-Null
}

function Grant-ServicePrincipalAppRoleAssignment {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PrincipalObjectId,
    [Parameter(Mandatory = $true)]
    [string]$ResourceAppId,
    [Parameter(Mandatory = $true)]
    [Guid]$AppRoleId
  )

  $spResponse = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=id" -f $ResourceAppId)
  if (-not $spResponse.value -or $spResponse.value.Count -eq 0) {
    throw "Service principal for resource appId '$ResourceAppId' was not found in this tenant."
  }

  $resourceSpId = $spResponse.value[0].id
  $existing = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalObjectId/appRoleAssignments"
  $match = @($existing.value | Where-Object { $_.resourceId -eq $resourceSpId -and $_.appRoleId -eq $AppRoleId }) | Select-Object -First 1
  if ($match) {
    return $null
  }

  $body = @{
    principalId = $PrincipalObjectId
    resourceId  = $resourceSpId
    appRoleId   = $AppRoleId
  } | ConvertTo-Json

  $created = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalObjectId/appRoleAssignments" -Body $body -ContentType 'application/json'
  if ($created -and $created.id) {
    return $created.id
  }

  return $null
}

function Get-DirectoryRoleDefinitionId {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RoleDisplayName
  )

  $escaped = $RoleDisplayName.Replace("'", "''")
  $defs = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq '{0}'&`$select=id,displayName" -f $escaped)
  if (-not $defs.value -or $defs.value.Count -eq 0) {
    throw "Directory role definition '$RoleDisplayName' was not found."
  }

  return $defs.value[0].id
}

function Get-DirectoryRoleAssignmentId {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PrincipalObjectId,
    [Parameter(Mandatory = $true)]
    [string]$RoleDefinitionId
  )

  $existing = Invoke-MgGraphRequest -Method GET -Uri (
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '{0}' and roleDefinitionId eq '{1}' and directoryScopeId eq '/'&`$select=id" -f $PrincipalObjectId, $RoleDefinitionId
  )

  if ($existing.value -and $existing.value.Count -gt 0) {
    return $existing.value[0].id
  }

  return $null
}

function Ensure-DirectoryRoleAssignment {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PrincipalObjectId,
    [Parameter(Mandatory = $true)]
    [string]$RoleDisplayName
  )

  $roleDefinitionId = Get-DirectoryRoleDefinitionId -RoleDisplayName $RoleDisplayName

  $existingId = Get-DirectoryRoleAssignmentId -PrincipalObjectId $PrincipalObjectId -RoleDefinitionId $roleDefinitionId
  if ($existingId) {
    return $null
  }

  $body = @{
    principalId      = $PrincipalObjectId
    roleDefinitionId = $roleDefinitionId
    directoryScopeId = '/'
  } | ConvertTo-Json

  $created = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' -Body $body -ContentType 'application/json'
  if ($created -and $created.id) {
    return $created.id
  }

  return $null
}

function Ensure-AzureReaderRoleAssignment {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Scope,
    [Parameter(Mandatory = $true)]
    [string]$PrincipalObjectId,
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId
  )

  $readerRoleGuid = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
  $roleDefinitionId = if ($Scope -like '/providers/Microsoft.Management/managementGroups/*') {
    "/providers/Microsoft.Authorization/roleDefinitions/$readerRoleGuid"
  }
  else {
    "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$readerRoleGuid"
  }

  # Pre-check: look for an existing Reader assignment for this principal at this scope
  $existingPath = "$Scope/providers/Microsoft.Authorization/roleAssignments?`$filter=principalId eq '$PrincipalObjectId' and atScope()&api-version=2022-04-01"
  $existingResponse = Invoke-AzRestMethod -Method GET -Path $existingPath
  if ($existingResponse.StatusCode -eq 200) {
    $existingPayload = $existingResponse.Content | ConvertFrom-Json
    $existingMatch = @($existingPayload.value | Where-Object {
        $_.properties.roleDefinitionId -like "*$readerRoleGuid"
      }) | Select-Object -First 1
    if ($existingMatch) {
      return $null
    }
  }

  $assignmentName = [guid]::NewGuid().ToString()
  $path = "$Scope/providers/Microsoft.Authorization/roleAssignments/${assignmentName}?api-version=2022-04-01"
  $body = @{
    properties = @{
      roleDefinitionId = $roleDefinitionId
      principalId      = $PrincipalObjectId
      principalType    = 'ServicePrincipal'
    }
  } | ConvertTo-Json -Depth 10

  $response = Invoke-AzRestMethod -Method PUT -Path $path -Payload $body
  if ($response.StatusCode -in @(200, 201)) {
    $payload = $response.Content | ConvertFrom-Json
    if ($payload -and $payload.id) {
      return $payload.id
    }
    return $null
  }

  # 409 Conflict means the assignment already exists (race condition with pre-check)
  if ($response.StatusCode -eq 409) {
    return $null
  }

  # Any other non-success status is a real error
  $errorContent = $response.Content
  throw "Azure RBAC Reader assignment failed at scope '$Scope'. HTTP $($response.StatusCode): $errorContent"
}

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

if (-not $PSBoundParameters.ContainsKey('IncludeExchange')) {
  $IncludeExchange = ConvertTo-BoolOrDefault -Value $env:INCLUDE_EXCHANGE -Default $false
}
if (-not $PSBoundParameters.ContainsKey('IncludeTeams')) {
  $IncludeTeams = ConvertTo-BoolOrDefault -Value $env:INCLUDE_TEAMS -Default $false
}
if (-not $PSBoundParameters.ContainsKey('IncludeAzure')) {
  $IncludeAzure = ConvertTo-BoolOrDefault -Value $env:INCLUDE_AZURE -Default $false
}

if (-not $PSBoundParameters.ContainsKey('AzureScopes')) {
  if ($env:AZURE_RBAC_SCOPES) {
    $rawScopes = $env:AZURE_RBAC_SCOPES.Trim()
    if ($rawScopes.StartsWith('[')) {
      try {
        $parsed = $rawScopes | ConvertFrom-Json
        if ($parsed -is [string]) {
          $AzureScopes = @($parsed)
        }
        elseif ($parsed) {
          $AzureScopes = @($parsed)
        }
      }
      catch {
        Write-Warning "AZURE_RBAC_SCOPES looked like JSON but could not be parsed. Falling back to ';' splitting. Value: $rawScopes"
        $AzureScopes = @($rawScopes -split ';' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
      }
    }
    else {
      $AzureScopes = @($rawScopes -split ';' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
  }
}

if ($IncludeAzure -and (-not $AzureScopes -or $AzureScopes.Count -eq 0)) {
  $AzureScopes = @("/subscriptions/$SubscriptionId")
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
  Connect-MgGraphSilent -TenantId $TenantId -Scopes 'User.Read','Directory.Read.All'
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

  $userLabel = if ($signedInUser.userPrincipalName) { $signedInUser.userPrincipalName } else { $signedInUser.id }
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
    Write-Host "Granted Storage Blob Data Reader on '$($storageAccount.name)' to signed-in user '$userLabel'."
  }
  else {
    Write-Host "Storage Blob Data Reader on '$($storageAccount.name)' is already assigned to '$userLabel'."
  }
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
  $foundNames = @($automationPayload.value | ForEach-Object { $_.name } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  $foundList = if ($foundNames.Count -gt 0) { $foundNames -join ', ' } else { 'none' }
  throw "Expected Automation Account '$preferredAutomationAccountName' was not found in resource group '$resolvedResourceGroupName'. Found: $foundList. This usually indicates provisioning failed (often quota-related), and setup cannot continue."
}

$automationAccountName = $automationAccount.name

$principalId = & "$PSScriptRoot\Get-ManagedIdentityPrincipal.ps1" `
  -SubscriptionId $SubscriptionId `
  -ResourceGroupName $resolvedResourceGroupName `
  -ProviderNamespace 'Microsoft.Automation' `
  -ResourceType 'automationAccounts' `
  -ResourceName $automationAccountName `
  -ApiVersion '2023-11-01'

Set-AzdEnvValue -Name 'AUTOMATION_MI_PRINCIPAL_ID' -Value $principalId

& "$PSScriptRoot\Grant-MaesterGraphPermissions.ps1" `
  -TenantId $TenantId `
  -PrincipalObjectId $principalId `
  -PermissionProfile $PermissionProfile

Write-Host "Automation account '$automationAccountName' managed identity is configured for Maester Graph permissions."

$exchangeSetupStatus = if ($IncludeExchange) { 'pending' } else { 'disabled' }
$teamsSetupStatus = if ($IncludeTeams) { 'pending' } else { 'disabled' }
$azureSetupStatus = if ($IncludeAzure) { 'pending' } else { 'disabled' }

$exoAppRoleAssignmentIds = @()
$teamsRoleAssignmentIds = @()
$azureRoleAssignmentIds = @()
$exoServicePrincipalDisplayName = $null

if ($IncludeExchange -or $IncludeTeams) {
  try {
    $scopes = @(
      'Application.Read.All',
      'AppRoleAssignment.ReadWrite.All',
      'Directory.Read.All',
      'Directory.AccessAsUser.All',
      'RoleManagement.ReadWrite.Directory'
    )
    Connect-MgGraphSilent -TenantId $TenantId -Scopes $scopes
  }
  catch {
    $action = Resolve-StepFailureAction -StepName 'Microsoft Graph connection for advanced setup' -Message $_.Exception.Message
    if ($action -eq 'Stop') {
      throw
    }
    $exchangeSetupStatus = if ($IncludeExchange) { 'skipped' } else { $exchangeSetupStatus }
    $teamsSetupStatus = if ($IncludeTeams) { 'skipped' } else { $teamsSetupStatus }
  }
}

if ($IncludeExchange -and $exchangeSetupStatus -eq 'pending') {
  $exchangeAppRoleOk = $false
  $exchangeRbacOk = $false

  try {
    $exchangeResourceAppId = '00000002-0000-0ff1-ce00-000000000000'
    $exchangeManageAsAppRoleId = [Guid]'dc50a0fb-09a3-484d-be87-e023b12c6440'

    $newAssignmentId = Grant-ServicePrincipalAppRoleAssignment -PrincipalObjectId $principalId -ResourceAppId $exchangeResourceAppId -AppRoleId $exchangeManageAsAppRoleId
    if ($newAssignmentId) {
      $exoAppRoleAssignmentIds += $newAssignmentId
      Write-Host 'Assigned Exchange.ManageAsApp to the Automation Account managed identity.'
    }
    else {
      Write-Host 'Exchange.ManageAsApp is already assigned to the Automation Account managed identity.'
    }
    $exchangeAppRoleOk = $true
  }
  catch {
    $action = Resolve-StepFailureAction -StepName 'Exchange app role assignment (Exchange.ManageAsApp)' -Message $_.Exception.Message
    if ($action -eq 'Stop') {
      throw
    }
  }

  try {
    $miSp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/${principalId}?`$select=id,appId,displayName"
    if (-not $miSp -or -not $miSp.appId) {
      throw 'Could not resolve managed identity service principal appId for Exchange setup.'
    }

    $exoServicePrincipalDisplayName = $miSp.displayName

    $installMsg = "Exchange Online PowerShell is required to grant the managed identity the Exchange RBAC role 'View-Only Configuration'."
    if (-not (Ensure-ModuleAvailable -ModuleName 'ExchangeOnlineManagement' -InstallMessage $installMsg)) {
      throw 'ExchangeOnlineManagement module is not available. Install it and rerun setup with -IncludeExchange.'
    }

    # Resolve tenant initial domain for Exchange AccessToken connection
    $exoOrganization = $null
    try {
      $orgResponse = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains'
      if ($orgResponse.value -and $orgResponse.value.Count -gt 0) {
        $initialDomain = @($orgResponse.value[0].verifiedDomains | Where-Object { $_.isInitial -eq $true }) | Select-Object -First 1
        if ($initialDomain) {
          $exoOrganization = $initialDomain.name
        }
      }
    }
    catch {
      Write-Verbose "Could not resolve tenant initial domain: $($_.Exception.Message)"
    }

    Connect-ExchangeOnlineSilent -Organization $exoOrganization

    try {
      New-ServicePrincipal -AppId $miSp.appId -ObjectId $principalId -DisplayName $miSp.displayName | Out-Null
      Write-Host "Created/linked Exchange service principal for '$($miSp.displayName)'."
    }
    catch {
      Write-Verbose ("New-ServicePrincipal returned an error (often safe to ignore if it already exists): {0}" -f $_.Exception.Message)
    }

    try {
      $roleAssignment = New-ManagementRoleAssignment -Role 'View-Only Configuration' -App $miSp.displayName -ErrorAction Stop
      if ($roleAssignment -and $roleAssignment.Identity) {
        Write-Host "Assigned Exchange RBAC role 'View-Only Configuration' to '$($miSp.displayName)'."
      }
      else {
        Write-Host "Ensured Exchange RBAC role 'View-Only Configuration' is assigned to '$($miSp.displayName)'."
      }
      $exchangeRbacOk = $true
    }
    catch {
      $message = $_.Exception.Message
      if ($message -match 'already exists') {
        Write-Host "Exchange RBAC role 'View-Only Configuration' is already assigned to '$($miSp.displayName)'."
        $exchangeRbacOk = $true
      }
      else {
        throw
      }
    }
  }
  catch {
    $action = Resolve-StepFailureAction -StepName 'Exchange RBAC assignment (View-Only Configuration)' -Message $_.Exception.Message
    if ($action -eq 'Stop') {
      throw
    }
  }

  if ($exchangeAppRoleOk -and $exchangeRbacOk) {
    $exchangeSetupStatus = 'configured'
  }
  else {
    $exchangeSetupStatus = 'skipped'
  }
}

if ($IncludeTeams -and $teamsSetupStatus -eq 'pending') {
  try {
    $newTeamsRoleAssignmentId = Ensure-DirectoryRoleAssignment -PrincipalObjectId $principalId -RoleDisplayName 'Teams Reader'
    if ($newTeamsRoleAssignmentId) {
      $teamsRoleAssignmentIds += $newTeamsRoleAssignmentId
      Write-Host "Assigned Entra directory role 'Teams Reader' to the Automation Account managed identity."
    }
    else {
      Write-Host "Entra directory role 'Teams Reader' is already assigned to the Automation Account managed identity."
    }

    $teamsSetupStatus = 'configured'
  }
  catch {
    $action = Resolve-StepFailureAction -StepName "Teams Reader role assignment" -Message $_.Exception.Message
    if ($action -eq 'Stop') {
      throw
    }
    $teamsSetupStatus = 'skipped'
  }
}

if ($IncludeAzure -and $azureSetupStatus -eq 'pending') {
  $succeededScopes = 0
  foreach ($scope in @($AzureScopes)) {
    if ([string]::IsNullOrWhiteSpace($scope)) {
      continue
    }

    try {
      $newAzureAssignmentId = Ensure-AzureReaderRoleAssignment -Scope $scope -PrincipalObjectId $principalId -SubscriptionId $SubscriptionId
      if ($newAzureAssignmentId) {
        $azureRoleAssignmentIds += $newAzureAssignmentId
        Write-Host "Granted Azure RBAC Reader to Automation managed identity at scope: $scope"
      }
      else {
        Write-Host "Azure RBAC Reader already exists or was already satisfied at scope: $scope"
      }
      $succeededScopes++
    }
    catch {
      $action = Resolve-StepFailureAction -StepName "Azure RBAC Reader assignment at scope $scope" -Message $_.Exception.Message
      if ($action -eq 'Stop') {
        throw
      }
      continue
    }
  }

  $azureSetupStatus = if ($succeededScopes -gt 0) { 'configured' } else { 'skipped' }
}

Set-AzdEnvValue -Name 'SETUP_EXCHANGE_STATUS' -Value $exchangeSetupStatus
Set-AzdEnvValue -Name 'SETUP_TEAMS_STATUS' -Value $teamsSetupStatus
Set-AzdEnvValue -Name 'SETUP_AZURE_STATUS' -Value $azureSetupStatus

Set-AzdEnvJsonArray -Name 'EXO_APPROLE_ASSIGNMENT_IDS' -Values @($exoAppRoleAssignmentIds)
Set-AzdEnvJsonArray -Name 'TEAMS_READER_ROLE_ASSIGNMENT_IDS' -Values @($teamsRoleAssignmentIds)
Set-AzdEnvJsonArray -Name 'AZURE_ROLE_ASSIGNMENT_IDS' -Values @($azureRoleAssignmentIds)

if ($exoServicePrincipalDisplayName) {
  Set-AzdEnvValue -Name 'EXO_SERVICE_PRINCIPAL_DISPLAY_NAME' -Value $exoServicePrincipalDisplayName
}

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
    Connect-MgGraphSilent -TenantId $TenantId -Scopes 'Group.Read.All','Directory.Read.All'

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

  Connect-MgGraphSilent -TenantId $TenantId -Scopes 'Application.ReadWrite.All','Directory.Read.All','DelegatedPermissionGrant.ReadWrite.All'

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
