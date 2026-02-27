# Shared predown cleanup helpers for azd-maester solutions.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Maester-Helpers.psm1') -Force

function Remove-ResourceGroupLocks {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName
  )

  if ([string]::IsNullOrWhiteSpace($SubscriptionId) -or [string]::IsNullOrWhiteSpace($ResourceGroupName)) {
    return
  }

  Write-Host "Removing resource locks in '$ResourceGroupName' (if any)..."
  $locksUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Authorization/locks?api-version=2016-09-01"
  $locksRaw = & az rest --method get --url $locksUrl --subscription $SubscriptionId 2>$null
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($locksRaw)) {
    return
  }

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
      Write-Host '  Waiting for lock deletions to propagate...'
      Start-Sleep -Seconds 15
    }
  }
  catch {
    Write-Warning 'Failed to parse lock list response.'
  }
}

function Remove-TrackedDirectoryRoleAssignments {
  param(
    [Parameter(Mandatory = $false)]
    [AllowEmptyCollection()]
    [string[]]$AssignmentIds = @()
  )

  if (@($AssignmentIds).Count -eq 0) {
    return
  }

  Write-Host 'Removing Teams Reader Entra role assignments created by this environment...'
  foreach ($assignmentId in @($AssignmentIds)) {
    if ([string]::IsNullOrWhiteSpace($assignmentId)) {
      continue
    }

    & az rest --method delete --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/$assignmentId" | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Failed to remove Teams Reader role assignment id '$assignmentId'."
    }
  }
}

function Remove-TrackedAzureRoleAssignments {
  param(
    [Parameter(Mandatory = $false)]
    [AllowEmptyCollection()]
    [string[]]$RoleAssignmentIds = @()
  )

  if (@($RoleAssignmentIds).Count -eq 0) {
    return
  }

  Write-Host 'Removing Azure RBAC role assignments created by this environment...'
  foreach ($roleAssignmentId in @($RoleAssignmentIds)) {
    if ([string]::IsNullOrWhiteSpace($roleAssignmentId)) {
      continue
    }

    & az role assignment delete --ids $roleAssignmentId | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Failed to remove Azure RBAC role assignment id '$roleAssignmentId'."
    }
  }
}

function Remove-TrackedExchangeAppRoleAssignments {
  param(
    [Parameter(Mandatory = $false)]
    [string]$PrincipalObjectId,

    [Parameter(Mandatory = $false)]
    [AllowEmptyCollection()]
    [string[]]$AssignmentIds = @()
  )

  if ([string]::IsNullOrWhiteSpace($PrincipalObjectId) -or @($AssignmentIds).Count -eq 0) {
    return
  }

  Write-Host 'Removing Exchange appRoleAssignments created by this environment...'
  foreach ($assignmentId in @($AssignmentIds)) {
    if ([string]::IsNullOrWhiteSpace($assignmentId)) {
      continue
    }

    & az rest --method delete --url "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalObjectId/appRoleAssignments/$assignmentId" | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Failed to remove Exchange appRoleAssignment id '$assignmentId'."
    }
  }
}

function Remove-ExchangeRbacAssignments {
  param(
    [Parameter(Mandatory = $false)]
    [string]$RoleAssigneeDisplayName
  )

  if ([string]::IsNullOrWhiteSpace($RoleAssigneeDisplayName)) {
    return
  }

  Write-Host "Attempting Exchange RBAC cleanup for '$RoleAssigneeDisplayName' (best-effort)..."
  try {
    if (-not (Test-ModuleAvailable -ModuleName 'ExchangeOnlineManagement')) {
      Write-Warning 'ExchangeOnlineManagement module is not available. Skipping Exchange RBAC cleanup.'
      return
    }

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
    catch {
    }

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
      $assignments = Get-ManagementRoleAssignment -RoleAssignee $RoleAssigneeDisplayName -ErrorAction SilentlyContinue
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
      Remove-ServicePrincipal -Identity $RoleAssigneeDisplayName -Confirm:$false -ErrorAction SilentlyContinue
    }
    catch {
    }
  }
  catch {
    Write-Warning ("Exchange RBAC cleanup encountered an error. Skipping. Error: {0}" -f $_.Exception.Message)
  }
}

function Invoke-MaesterStandardPreDownCleanup {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('AUTOMATION_MI_PRINCIPAL_ID', 'FUNCTION_APP_MI_PRINCIPAL_ID', 'CONTAINER_JOB_MI_PRINCIPAL_ID')]
    [string]$ManagedIdentityPrincipalEnvName
  )

  $envValues = Get-AzdEnvironmentValues
  if (-not $envValues -or $envValues.Count -eq 0) {
    Write-Warning 'Could not load azd environment values during predown cleanup. Skipping.'
    return
  }

  $resourceGroupName = Get-AzdEnvironmentValue -Values $envValues -Name 'AZURE_RESOURCE_GROUP'
  $subscriptionId = Get-AzdEnvironmentValue -Values $envValues -Name 'AZURE_SUBSCRIPTION_ID'
  $easyAuthAppObjectId = Get-AzdEnvironmentValue -Values $envValues -Name 'EASY_AUTH_ENTRA_APP_OBJECT_ID'
  $easyAuthAppClientId = Get-AzdEnvironmentValue -Values $envValues -Name 'EASY_AUTH_ENTRA_APP_CLIENT_ID'
  $miPrincipalId = Get-AzdEnvironmentValue -Values $envValues -Name $ManagedIdentityPrincipalEnvName
  $teamsRoleAssignmentIds = @(ConvertFrom-JsonArrayOrEmpty -Json (Get-AzdEnvironmentValue -Values $envValues -Name 'TEAMS_READER_ROLE_ASSIGNMENT_IDS'))
  $azureRoleAssignmentIds = @(ConvertFrom-JsonArrayOrEmpty -Json (Get-AzdEnvironmentValue -Values $envValues -Name 'AZURE_ROLE_ASSIGNMENT_IDS'))
  $exoAppRoleAssignmentIds = @(ConvertFrom-JsonArrayOrEmpty -Json (Get-AzdEnvironmentValue -Values $envValues -Name 'EXO_APPROLE_ASSIGNMENT_IDS'))
  $exoServicePrincipalDisplayName = Get-AzdEnvironmentValue -Values $envValues -Name 'EXO_SERVICE_PRINCIPAL_DISPLAY_NAME'

  Remove-TrackedDirectoryRoleAssignments -AssignmentIds $teamsRoleAssignmentIds
  Remove-TrackedAzureRoleAssignments -RoleAssignmentIds $azureRoleAssignmentIds
  Remove-TrackedExchangeAppRoleAssignments -PrincipalObjectId $miPrincipalId -AssignmentIds $exoAppRoleAssignmentIds
  Remove-ExchangeRbacAssignments -RoleAssigneeDisplayName $exoServicePrincipalDisplayName

  if (-not [string]::IsNullOrWhiteSpace($resourceGroupName)) {
    Remove-WebAppEasyAuthEntraApplications `
      -ResourceGroupName $resourceGroupName `
      -SubscriptionId $subscriptionId `
      -AdditionalApplicationObjectIds @($easyAuthAppObjectId) `
      -AdditionalClientIds @($easyAuthAppClientId)
  }

  Remove-ResourceGroupLocks -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName
}

function ConvertTo-PlainTextToken {
  param(
    [Parameter(Mandatory = $true)]
    $TokenValue
  )

  if ($TokenValue -is [string]) {
    return $TokenValue
  }

  if ($TokenValue -is [System.Security.SecureString]) {
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($TokenValue)
    try {
      return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
      [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
  }

  return [string]$TokenValue
}

function Invoke-AdoRest {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
    [string]$Method,

    [Parameter(Mandatory = $true)]
    [string]$Uri,

    [Parameter(Mandatory = $false)]
    $Body,

    [Parameter(Mandatory = $false)]
    [switch]$AllowNotFound
  )

  $invokeParams = @{
    Method     = $Method
    Uri        = $Uri
    ResourceId = '499b84ac-1321-427f-aa17-267ca6975798'
  }

  if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
    if ($Body -is [string]) {
      $invokeParams['Payload'] = $Body
    }
    else {
      $invokeParams['Payload'] = ($Body | ConvertTo-Json -Depth 20 -Compress)
    }
  }

  $response = Invoke-AzRestMethod @invokeParams
  $statusCode = 0
  [void][int]::TryParse(([string]$response.StatusCode), [ref]$statusCode)
  if ($statusCode -eq 404 -and $AllowNotFound) {
    return $null
  }
  if ($statusCode -ge 400) {
    $message = $null
    if (-not [string]::IsNullOrWhiteSpace($response.Content)) {
      try {
        $errorPayload = $response.Content | ConvertFrom-Json
        if ($errorPayload.PSObject.Properties['message']) {
          $message = [string]$errorPayload.message
        }
        elseif ($errorPayload.PSObject.Properties['value'] -and $errorPayload.value.PSObject.Properties['Message']) {
          $message = [string]$errorPayload.value.Message
        }
      }
      catch {
      }
    }

    if ([string]::IsNullOrWhiteSpace($message)) {
      throw "Azure DevOps REST call failed with status ${statusCode}: $Method $Uri"
    }

    throw "Azure DevOps REST call failed with status ${statusCode}: $Method $Uri. $message"
  }

  if ($null -eq $response -or [string]::IsNullOrWhiteSpace($response.Content)) {
    return $null
  }

  try {
    return ($response.Content | ConvertFrom-Json)
  }
  catch {
    return $response.Content
  }
}

function Remove-AdoServiceConnectionById {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [string]$ProjectEncoded,

    [Parameter(Mandatory = $true)]
    [string]$ServiceConnectionId,

    [Parameter(Mandatory = $false)]
    [string]$ProjectId
  )

  $deleteUris = @()
  if (-not [string]::IsNullOrWhiteSpace($ProjectId)) {
    $deleteUris += "https://dev.azure.com/$Organization/$ProjectEncoded/_apis/serviceendpoint/endpoints/$($ServiceConnectionId)?projectIds=$ProjectId&api-version=7.1-preview.4"
  }
  $deleteUris += "https://dev.azure.com/$Organization/$ProjectEncoded/_apis/serviceendpoint/endpoints/$($ServiceConnectionId)?api-version=7.1-preview.4"

  foreach ($deleteUri in @($deleteUris | Select-Object -Unique)) {
    try {
      Invoke-AdoRest -Method DELETE -Uri $deleteUri -AllowNotFound | Out-Null
      $verificationUri = "https://dev.azure.com/$Organization/$ProjectEncoded/_apis/serviceendpoint/endpoints/$($ServiceConnectionId)?api-version=7.1-preview.4"
      $maxVerifyAttempts = 6
      for ($attempt = 1; $attempt -le $maxVerifyAttempts; $attempt++) {
        $verification = Invoke-AdoRest -Method GET -Uri $verificationUri -AllowNotFound
        if ($null -eq $verification) {
          return $true
        }

        if ($attempt -lt $maxVerifyAttempts) {
          Start-Sleep -Seconds 5
        }
      }
    }
    catch {
      Write-Verbose ("Service connection delete attempt failed for URI '{0}'. Error: {1}" -f $deleteUri, $_.Exception.Message)
    }
  }

  return $false
}

function Remove-TrackedBaseRoleAssignments {
  param(
    [Parameter(Mandatory = $false)]
    [AllowEmptyCollection()]
    [string[]]$RoleAssignmentIds = @()
  )

  if (@($RoleAssignmentIds).Count -eq 0) {
    return
  }

  Write-Host 'Removing base Azure role assignments created for Azure DevOps workload identity...'
  foreach ($roleAssignmentId in @($RoleAssignmentIds)) {
    if ([string]::IsNullOrWhiteSpace($roleAssignmentId)) {
      continue
    }

    & az role assignment delete --ids $roleAssignmentId | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Failed to remove base role assignment id '$roleAssignmentId'."
    }
  }
}

function Invoke-MaesterAzureDevOpsPreDownCleanup {
  [CmdletBinding()]
  param()

  Import-Module Az.Accounts -Force

  $envValues = Get-AzdEnvironmentValues
  if (-not $envValues -or $envValues.Count -eq 0) {
    Write-Warning 'Could not load azd environment values during Azure DevOps predown cleanup. Skipping.'
    return
  }

  $resourceGroupName = Get-AzdEnvironmentValue -Values $envValues -Name 'AZURE_RESOURCE_GROUP'
  $subscriptionId = Get-AzdEnvironmentValue -Values $envValues -Name 'AZURE_SUBSCRIPTION_ID'
  $tenantId = Get-AzdEnvironmentValue -Values $envValues -Name 'AZURE_TENANT_ID'
  $adoOrganization = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_ORGANIZATION'
  $adoProject = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_PROJECT'
  $adoRepositoryName = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_REPOSITORY'
  $adoRepositoryId = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_REPOSITORY_ID'
  $adoPipelineName = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_PIPELINE_NAME'
  $adoPipelineId = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_PIPELINE_ID'
  $adoServiceConnectionName = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_SERVICE_CONNECTION_NAME'
  $adoServiceConnectionId = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_SERVICE_CONNECTION_ID'
  $workloadAppId = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_WORKLOAD_APP_ID'
  $workloadAppObjectId = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_WORKLOAD_APP_OBJECT_ID'
  $workloadServicePrincipalObjectId = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_WORKLOAD_SERVICE_PRINCIPAL_OBJECT_ID'
  $easyAuthAppObjectId = Get-AzdEnvironmentValue -Values $envValues -Name 'EASY_AUTH_ENTRA_APP_OBJECT_ID'
  $easyAuthAppClientId = Get-AzdEnvironmentValue -Values $envValues -Name 'EASY_AUTH_ENTRA_APP_CLIENT_ID'
  $exoServicePrincipalDisplayName = Get-AzdEnvironmentValue -Values $envValues -Name 'EXO_SERVICE_PRINCIPAL_DISPLAY_NAME'
  $workloadIdentityDisplayName = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_WORKLOAD_IDENTITY_DISPLAY_NAME'

  $baseRoleAssignmentIds = @(ConvertFrom-JsonArrayOrEmpty -Json (Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_BASE_ROLE_ASSIGNMENT_IDS'))
  $teamsRoleAssignmentIds = @(ConvertFrom-JsonArrayOrEmpty -Json (Get-AzdEnvironmentValue -Values $envValues -Name 'TEAMS_READER_ROLE_ASSIGNMENT_IDS'))
  $azureRoleAssignmentIds = @(ConvertFrom-JsonArrayOrEmpty -Json (Get-AzdEnvironmentValue -Values $envValues -Name 'AZURE_ROLE_ASSIGNMENT_IDS'))
  $exoAppRoleAssignmentIds = @(ConvertFrom-JsonArrayOrEmpty -Json (Get-AzdEnvironmentValue -Values $envValues -Name 'EXO_APPROLE_ASSIGNMENT_IDS'))

  if ([string]::IsNullOrWhiteSpace($exoServicePrincipalDisplayName) -and -not [string]::IsNullOrWhiteSpace($workloadIdentityDisplayName)) {
    $exoServicePrincipalDisplayName = $workloadIdentityDisplayName
  }

  if (-not [string]::IsNullOrWhiteSpace($workloadServicePrincipalObjectId) -and @($exoAppRoleAssignmentIds).Count -eq 0) {
    try {
      $exchangeManageAsAppRoleId = 'dc50a0fb-09a3-484d-be87-e023b12c6440'
      $appAssignmentsUrl = "https://graph.microsoft.com/v1.0/servicePrincipals/$workloadServicePrincipalObjectId/appRoleAssignments?`$select=id,appRoleId"
      $appAssignmentsRaw = & az rest --method get --url $appAssignmentsUrl 2>$null
      if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($appAssignmentsRaw)) {
        $appAssignmentsPayload = $appAssignmentsRaw | ConvertFrom-Json
        $resolvedAssignmentIds = @($appAssignmentsPayload.value | Where-Object { $_.appRoleId -eq $exchangeManageAsAppRoleId } | ForEach-Object { $_.id } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($resolvedAssignmentIds.Count -gt 0) {
          $exoAppRoleAssignmentIds = @($resolvedAssignmentIds)
          Write-Host "Resolved $($exoAppRoleAssignmentIds.Count) Exchange appRoleAssignment id(s) from Microsoft Graph for cleanup."
        }
      }
    }
    catch {
      Write-Warning "Could not resolve Exchange appRoleAssignments for cleanup. Error: $($_.Exception.Message)"
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($subscriptionId)) {
    $existingContext = Get-AzContext -ErrorAction SilentlyContinue
    $requiresLogin = $true
    if ($existingContext -and $existingContext.Subscription -and $existingContext.Subscription.Id -eq $subscriptionId) {
      if (-not $tenantId -or ($existingContext.Tenant -and $existingContext.Tenant.Id -eq $tenantId)) {
        $requiresLogin = $false
      }
    }

    if ($requiresLogin) {
      $connectParameters = @{ Subscription = $subscriptionId }
      if ($tenantId) {
        $connectParameters['Tenant'] = $tenantId
      }
      Connect-AzAccount @connectParameters | Out-Null
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($resourceGroupName) -and -not [string]::IsNullOrWhiteSpace($subscriptionId)) {
    Remove-ResourceGroupLocks -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName
  }

  Remove-TrackedDirectoryRoleAssignments -AssignmentIds $teamsRoleAssignmentIds
  Remove-TrackedAzureRoleAssignments -RoleAssignmentIds $azureRoleAssignmentIds
  Remove-TrackedBaseRoleAssignments -RoleAssignmentIds $baseRoleAssignmentIds
  Remove-TrackedExchangeAppRoleAssignments -PrincipalObjectId $workloadServicePrincipalObjectId -AssignmentIds $exoAppRoleAssignmentIds

  $exchangeIdentityCandidates = @(
    @(
      $exoServicePrincipalDisplayName,
      $workloadIdentityDisplayName,
      $workloadAppId,
      $workloadServicePrincipalObjectId
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
  )

  foreach ($identity in $exchangeIdentityCandidates) {
    Remove-ExchangeRbacAssignments -RoleAssigneeDisplayName $identity
  }

  $adoProjectEncoded = $null
  $adoProjectId = $null
  $retryAdoServiceConnectionId = $null
  $retryAdoServiceConnectionName = $null

  if (-not [string]::IsNullOrWhiteSpace($adoOrganization) -and -not [string]::IsNullOrWhiteSpace($adoProject)) {
    try {
      $adoProjectEncoded = [System.Uri]::EscapeDataString($adoProject)

      try {
        $projectResponse = Invoke-AdoRest -Method GET -Uri "https://dev.azure.com/$adoOrganization/_apis/projects/$($adoProjectEncoded)?api-version=7.1-preview.4"
        if ($projectResponse -and $projectResponse.id) {
          $adoProjectId = [string]$projectResponse.id
        }
      }
      catch {
        Write-Warning "Failed to resolve Azure DevOps project id for '$adoProject'. Service connection cleanup may be incomplete. Error: $($_.Exception.Message)"
      }

      if (-not [string]::IsNullOrWhiteSpace($adoPipelineId)) {
        Write-Host "Removing Azure DevOps pipeline '$adoPipelineName' ($adoPipelineId)..."
        Invoke-AdoRest -Method DELETE -Uri "https://dev.azure.com/$adoOrganization/$adoProjectEncoded/_apis/build/definitions/$($adoPipelineId)?api-version=7.1" | Out-Null
      }
      elseif (-not [string]::IsNullOrWhiteSpace($adoPipelineName)) {
        try {
          $pipelines = Invoke-AdoRest -Method GET -Uri "https://dev.azure.com/$adoOrganization/$adoProjectEncoded/_apis/pipelines?api-version=7.1-preview.1"
          $pipeline = @($pipelines.value | Where-Object { $_.name -eq $adoPipelineName } | Select-Object -First 1)
          if ($pipeline.Count -gt 0 -and $pipeline[0].id) {
            Write-Host "Removing Azure DevOps pipeline '$adoPipelineName' ($($pipeline[0].id))..."
            Invoke-AdoRest -Method DELETE -Uri "https://dev.azure.com/$adoOrganization/$adoProjectEncoded/_apis/build/definitions/$($pipeline[0].id)?api-version=7.1" | Out-Null
          }
        }
        catch {
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($adoServiceConnectionId)) {
        Write-Host "Removing Azure DevOps service connection '$adoServiceConnectionName' ($adoServiceConnectionId)..."
        $removed = Remove-AdoServiceConnectionById -Organization $adoOrganization -ProjectEncoded $adoProjectEncoded -ServiceConnectionId $adoServiceConnectionId -ProjectId $adoProjectId
        if (-not $removed) {
          Write-Warning "Failed to remove Azure DevOps service connection id '$adoServiceConnectionId'."
          $retryAdoServiceConnectionId = $adoServiceConnectionId
          $retryAdoServiceConnectionName = $adoServiceConnectionName
        }
      }
      elseif (-not [string]::IsNullOrWhiteSpace($adoServiceConnectionName)) {
        try {
          $encodedEndpointName = [System.Uri]::EscapeDataString($adoServiceConnectionName)
          $serviceConnections = Invoke-AdoRest -Method GET -Uri "https://dev.azure.com/$adoOrganization/$adoProjectEncoded/_apis/serviceendpoint/endpoints?endpointNames=$encodedEndpointName&includeFailed=true&api-version=7.1-preview.4"
          $serviceConnection = @($serviceConnections.value | Where-Object { $_.name -eq $adoServiceConnectionName } | Select-Object -First 1)
          if ($serviceConnection.Count -gt 0 -and $serviceConnection[0].id) {
            Write-Host "Removing Azure DevOps service connection '$adoServiceConnectionName' ($($serviceConnection[0].id))..."
            $removed = Remove-AdoServiceConnectionById -Organization $adoOrganization -ProjectEncoded $adoProjectEncoded -ServiceConnectionId ([string]$serviceConnection[0].id) -ProjectId $adoProjectId
            if (-not $removed) {
              Write-Warning "Failed to remove Azure DevOps service connection '$adoServiceConnectionName' ($($serviceConnection[0].id))."
              $retryAdoServiceConnectionId = [string]$serviceConnection[0].id
              $retryAdoServiceConnectionName = $adoServiceConnectionName
            }
          }
        }
        catch {
        }
      }

      if (-not [string]::IsNullOrWhiteSpace($adoRepositoryId)) {
        Write-Host "Removing Azure DevOps repository '$adoRepositoryName' ($adoRepositoryId)..."
        Invoke-AdoRest -Method DELETE -Uri "https://dev.azure.com/$adoOrganization/$adoProjectEncoded/_apis/git/repositories/$($adoRepositoryId)?api-version=7.1-preview.1" | Out-Null
      }
      elseif (-not [string]::IsNullOrWhiteSpace($adoRepositoryName)) {
        try {
          $repos = Invoke-AdoRest -Method GET -Uri "https://dev.azure.com/$adoOrganization/$adoProjectEncoded/_apis/git/repositories?api-version=7.1-preview.1"
          $repo = @($repos.value | Where-Object { $_.name -eq $adoRepositoryName } | Select-Object -First 1)
          if ($repo.Count -gt 0 -and $repo[0].id) {
            Write-Host "Removing Azure DevOps repository '$adoRepositoryName' ($($repo[0].id))..."
            Invoke-AdoRest -Method DELETE -Uri "https://dev.azure.com/$adoOrganization/$adoProjectEncoded/_apis/git/repositories/$($repo[0].id)?api-version=7.1-preview.1" | Out-Null
          }
        }
        catch {
        }
      }
    }
    catch {
      Write-Warning "Azure DevOps cleanup encountered an error. Continuing with remaining cleanup. Error: $($_.Exception.Message)"
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($workloadAppObjectId)) {
    Write-Host "Removing workload identity Entra application object '$workloadAppObjectId'..."
    & az rest --method delete --url "https://graph.microsoft.com/v1.0/applications/$workloadAppObjectId" | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Failed to remove Entra application object '$workloadAppObjectId'."
    }
  }
  elseif (-not [string]::IsNullOrWhiteSpace($workloadAppId)) {
    Write-Host "Removing workload identity Entra application appId '$workloadAppId'..."
    & az ad app delete --id $workloadAppId | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Failed to remove Entra application appId '$workloadAppId'."
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($retryAdoServiceConnectionId) -and
      -not [string]::IsNullOrWhiteSpace($adoOrganization) -and
      -not [string]::IsNullOrWhiteSpace($adoProjectEncoded)) {
    Write-Host "Retrying Azure DevOps service connection '$retryAdoServiceConnectionName' ($retryAdoServiceConnectionId) after workload identity cleanup..."
    Start-Sleep -Seconds 10
    $removed = Remove-AdoServiceConnectionById -Organization $adoOrganization -ProjectEncoded $adoProjectEncoded -ServiceConnectionId $retryAdoServiceConnectionId -ProjectId $adoProjectId
    if (-not $removed) {
      Write-Warning "Retry failed for Azure DevOps service connection '$retryAdoServiceConnectionName' ($retryAdoServiceConnectionId)."
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($resourceGroupName)) {
    Remove-WebAppEasyAuthEntraApplications `
      -ResourceGroupName $resourceGroupName `
      -SubscriptionId $subscriptionId `
      -AdditionalApplicationObjectIds @($easyAuthAppObjectId) `
      -AdditionalClientIds @($easyAuthAppClientId)
  }

  Write-Host 'Azure DevOps predown cleanup completed.'
}

Export-ModuleMember -Function Invoke-MaesterStandardPreDownCleanup, Invoke-MaesterAzureDevOpsPreDownCleanup
