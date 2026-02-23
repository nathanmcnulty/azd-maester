# Shared setup helper functions for azd-maester solutions
# Imported by Setup-PostDeploy.ps1 and Start-Setup.ps1 in each solution.

# ── Utilities ────────────────────────────────────────────────────────────────

function Test-CanPrompt {
  try {
    $null = $Host.UI.RawUI
    return $true
  }
  catch {
    return $false
  }
}

function Test-CommandExists {
  param([Parameter(Mandatory = $true)][string]$CommandName)
  return [bool](Get-Command -Name $CommandName -ErrorAction SilentlyContinue)
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

function Test-ModuleAvailable {
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

# ── azd env helpers ──────────────────────────────────────────────────────────

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

# ── Authentication helpers ────────────────────────────────────────────────────

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

function Confirm-AzureLogin {
  try {
    $null = az account show --output none 2>$null
    if ($LASTEXITCODE -eq 0) {
      return
    }
  }
  catch {
  }

  Write-Host 'No active Azure CLI login detected. Opening Azure login...'
  & az login | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw 'Azure login failed.'
  }
}

function Select-Subscription {
  param([Parameter(Mandatory = $false)][string]$RequestedSubscriptionId)

  if (-not [string]::IsNullOrWhiteSpace($RequestedSubscriptionId)) {
    & az account set --subscription $RequestedSubscriptionId
    if ($LASTEXITCODE -ne 0) {
      throw "Could not select subscription '$RequestedSubscriptionId'."
    }
    return $RequestedSubscriptionId
  }

  $subscriptionsJson = az account list --query "[].{name:name,id:id,isDefault:isDefault,tenantId:tenantId}" -o json
  if ($LASTEXITCODE -ne 0) {
    throw 'Failed to enumerate subscriptions.'
  }

  $subscriptions = $subscriptionsJson | ConvertFrom-Json
  if (-not $subscriptions -or $subscriptions.Count -eq 0) {
    throw 'No Azure subscriptions available for the signed-in account.'
  }

  if ($subscriptions.Count -eq 1) {
    $singleId = $subscriptions[0].id
    Write-Host "Using only available subscription: $($subscriptions[0].name) ($singleId)"
    & az account set --subscription $singleId
    if ($LASTEXITCODE -ne 0) {
      throw "Could not select subscription '$singleId'."
    }
    return $singleId
  }

  Write-Host 'Select a subscription:'
  for ($index = 0; $index -lt $subscriptions.Count; $index++) {
    $sub = $subscriptions[$index]
    $defaultMarker = if ($sub.isDefault) { ' (default)' } else { '' }
    Write-Host ("[{0}] {1} | {2}{3}" -f ($index + 1), $sub.name, $sub.id, $defaultMarker)
  }

  $selection = Read-Host 'Enter selection number'
  $selectionValue = 0
  if (-not [int]::TryParse($selection, [ref]$selectionValue)) {
    throw 'Subscription selection must be a number.'
  }

  $selectedIndex = $selectionValue - 1
  if ($selectedIndex -lt 0 -or $selectedIndex -ge $subscriptions.Count) {
    throw 'Subscription selection is out of range.'
  }

  $selectedId = $subscriptions[$selectedIndex].id
  & az account set --subscription $selectedId
  if ($LASTEXITCODE -ne 0) {
    throw "Could not select subscription '$selectedId'."
  }

  return $selectedId
}

function Select-AzureRbacScopes {
  param(
    [Parameter(Mandatory = $true)]
    [string]$DefaultSubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$ResourceTypeName = 'managed identity'
  )

  if (-not (Test-CanPrompt)) {
    Write-Warning "-IncludeAzure was specified but interactive prompting is not available. Defaulting Azure RBAC scope to subscription '/subscriptions/$DefaultSubscriptionId'."
    return @("/subscriptions/$DefaultSubscriptionId")
  }

  $items = @()

  try {
    $mgJson = & az account management-group list -o json 2>$null
    if ($LASTEXITCODE -eq 0 -and $mgJson) {
      $mgs = $mgJson | ConvertFrom-Json
      foreach ($mg in @($mgs)) {
        $mgName = if ($mg.name) { $mg.name } elseif ($mg.id -and ($mg.id -split '/')[-1]) { ($mg.id -split '/')[-1] } else { $null }
        if (-not $mgName) { continue }
        $mgDisplayName = if ($mg.displayName) { $mg.displayName } else { $mgName }
        $items += [pscustomobject]@{
          Label = "MG  | $mgDisplayName ($mgName)"
          Scope = "/providers/Microsoft.Management/managementGroups/$mgName"
        }
      }
    }
  }
  catch {
  }

  $subsJson = az account list --query "[].{name:name,id:id,isDefault:isDefault}" -o json
  if ($LASTEXITCODE -ne 0) {
    throw 'Failed to enumerate subscriptions for Azure scope selection.'
  }

  $subs = $subsJson | ConvertFrom-Json
  foreach ($sub in @($subs)) {
    $items += [pscustomobject]@{
      Label = "SUB | $($sub.name) ($($sub.id))"
      Scope = "/subscriptions/$($sub.id)"
    }
  }

  if ($items.Count -eq 0) {
    Write-Warning "No management groups or subscriptions were discovered. Defaulting Azure RBAC scope to subscription '/subscriptions/$DefaultSubscriptionId'."
    return @("/subscriptions/$DefaultSubscriptionId")
  }

  Write-Host "Select one or more Azure RBAC scopes to grant the $ResourceTypeName Reader access."
  Write-Host 'Enter one or more numbers separated by commas. Press Enter to use the current subscription.'
  for ($index = 0; $index -lt $items.Count; $index++) {
    Write-Host ("[{0}] {1}" -f ($index + 1), $items[$index].Label)
  }

  $selection = Read-Host 'Selection'
  if ([string]::IsNullOrWhiteSpace($selection)) {
    return @("/subscriptions/$DefaultSubscriptionId")
  }

  $selectedScopes = @()
  $parts = @($selection -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  foreach ($part in $parts) {
    $value = 0
    if (-not [int]::TryParse($part, [ref]$value)) {
      throw "Invalid selection '$part'. Expected a number or comma-separated numbers."
    }

    $selectedIndex = $value - 1
    if ($selectedIndex -lt 0 -or $selectedIndex -ge $items.Count) {
      throw "Selection '$value' is out of range."
    }

    $selectedScopes += $items[$selectedIndex].Scope
  }

  return @($selectedScopes | Sort-Object -Unique)
}

# ── Graph / Azure RBAC assignment helpers ────────────────────────────────────

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

function Test-DirectoryRoleAssignment {
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

function Test-AzureReaderRoleAssignment {
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
