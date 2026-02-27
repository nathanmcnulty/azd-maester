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
  [string[]]$AzureScopes,

  [Parameter(Mandatory = $false)]
  [string]$AdoOrganization,

  [Parameter(Mandatory = $false)]
  [string]$AdoProject,

  [Parameter(Mandatory = $false)]
  [string]$AdoRepositoryName,

  [Parameter(Mandatory = $false)]
  [string]$AdoPipelineName,

  [Parameter(Mandatory = $false)]
  [string]$AdoServiceConnectionName,

  [Parameter(Mandatory = $false)]
  [string]$PipelineYamlPath,

  [Parameter(Mandatory = $false)]
  [string]$DefaultBranch,

  [Parameter(Mandatory = $false)]
  [string]$ScheduleCron,

  [Parameter(Mandatory = $false)]
  [bool]$CreateRepositoryIfMissing,

  [Parameter(Mandatory = $false)]
  [bool]$PushPipelineFiles,

  [Parameter(Mandatory = $false)]
  [bool]$ValidatePipelineRun,

  [Parameter(Mandatory = $false)]
  [bool]$FailOnTestFailures
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-EnvValue {
  param(
    [Parameter(Mandatory = $true)]
    $Lines,

    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  if ($Lines -is [hashtable]) {
    if ($Lines.ContainsKey($Name)) {
      return [string]$Lines[$Name]
    }
    return $null
  }

  foreach ($line in @($Lines)) {
    if ($line -like "$Name=*") {
      return $line.Split('=', 2)[1].Trim('"')
    }
  }

  return $null
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

function Test-RequiredValue {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Value,

    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    throw "$Name is required."
  }

  return $Value.Trim()
}
function Get-OptionalPropertyValue {
  param(
    [Parameter(Mandatory = $false)]
    $InputObject,

    [Parameter(Mandatory = $true)]
    [string[]]$PropertyNames
  )

  if ($null -eq $InputObject) {
    return $null
  }

  foreach ($propertyName in $PropertyNames) {
    $property = $InputObject.PSObject.Properties | Where-Object { $_.Name -ieq $propertyName } | Select-Object -First 1
    if ($property) {
      return $property.Value
    }
  }

  return $null
}


function Get-FirstAuthorizedResourceMatch {
  param(
    [Parameter(Mandatory = $false)]
    $AuthorizedResourcesResponse,

    [Parameter(Mandatory = $true)]
    [string]$ResourceType,

    [Parameter(Mandatory = $true)]
    [string]$ResourceId
  )

  if ($null -eq $AuthorizedResourcesResponse) {
    return $null
  }

  $candidateItems = @()
  $responseValue = Get-OptionalPropertyValue -InputObject $AuthorizedResourcesResponse -PropertyNames @('value')
  if ($responseValue) {
    $candidateItems = @($responseValue)
  }
  else {
    $candidateItems = @($AuthorizedResourcesResponse)
  }

  if ($candidateItems.Count -eq 0) {
    return $null
  }

  return @($candidateItems | Where-Object {
      ([string](Get-OptionalPropertyValue -InputObject $_ -PropertyNames @('type')) -ieq $ResourceType) -and
      ([string](Get-OptionalPropertyValue -InputObject $_ -PropertyNames @('id')) -eq $ResourceId)
    }) | Select-Object -First 1
}

function Test-IsAuthorizedResource {
  param(
    [Parameter(Mandatory = $false)]
    $ResourceEntry
  )

  if ($null -eq $ResourceEntry) {
    return $false
  }

  $authorizedValue = Get-OptionalPropertyValue -InputObject $ResourceEntry -PropertyNames @('authorized')
  if ($authorizedValue -is [bool]) {
    return $authorizedValue
  }

  return ConvertTo-BoolOrDefault -Value ([string]$authorizedValue) -Default $false
}

function Test-AdoServiceConnectionAuthorizedForPipelines {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [string]$Project,

    [Parameter(Mandatory = $true)]
    [string]$ServiceConnectionId,

    [Parameter(Mandatory = $true)]
    [string]$ServiceConnectionName
  )

  $projectEncoded = [System.Uri]::EscapeDataString($Project)
  $permissionsUri = "https://dev.azure.com/$Organization/$projectEncoded/_apis/pipelines/pipelinePermissions/endpoint/$($ServiceConnectionId)?api-version=7.1-preview.1"
  $adoResourceId = '499b84ac-1321-427f-aa17-267ca6975798'

  $existingResponse = Invoke-AzRestMethod -Method GET -Uri $permissionsUri -ResourceId $adoResourceId
  if (-not [string]::IsNullOrWhiteSpace($existingResponse.Content)) {
    $existingPayload = $existingResponse.Content | ConvertFrom-Json
    if ($existingPayload -and $existingPayload.PSObject.Properties['allPipelines']) {
      $existingAuthorized = ConvertTo-BoolOrDefault -Value ([string]$existingPayload.allPipelines.authorized) -Default $false
      if ($existingAuthorized) {
        return $true
      }
    }
  }

  Write-Host "Granting pipeline access to service connection '$ServiceConnectionName'..."
  $patchBody = @{
    allPipelines = @{
      authorized = $true
    }
    pipelines = @()
  } | ConvertTo-Json -Depth 10 -Compress

  Invoke-AzRestMethod -Method PATCH -Uri $permissionsUri -ResourceId $adoResourceId -Payload $patchBody | Out-Null

  $verifiedResponse = Invoke-AzRestMethod -Method GET -Uri $permissionsUri -ResourceId $adoResourceId
  $verifiedAuthorized = $false
  if (-not [string]::IsNullOrWhiteSpace($verifiedResponse.Content)) {
    $verifiedPayload = $verifiedResponse.Content | ConvertFrom-Json
    if ($verifiedPayload -and $verifiedPayload.PSObject.Properties['allPipelines']) {
      $verifiedAuthorized = ConvertTo-BoolOrDefault -Value ([string]$verifiedPayload.allPipelines.authorized) -Default $false
    }
  }

  if (-not $verifiedAuthorized) {
    throw "Service connection '$ServiceConnectionName' was not authorized for pipelines. Grant permission in Azure DevOps and rerun setup."
  }

  return $true
}
function global:Invoke-MgGraphRequest {
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

function Invoke-GraphAuthProbe {
  param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    [Parameter(Mandatory = $false)]
    [string[]]$Scopes = @()
  )

  # Compatibility no-op: Graph calls use Invoke-AzRestMethod through Invoke-MgGraphRequest.
  try {
    Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id&$top=1' | Out-Null
  }
  catch {
    $scopeText = if ($Scopes -and $Scopes.Count -gt 0) { $Scopes -join ', ' } else { 'default Graph scopes' }
    throw "Microsoft Graph access check failed for tenant '$TenantId' (requested: $scopeText). Ensure Azure login is active and has Graph permissions. Error: $($_.Exception.Message)"
  }
}

function Test-AzureRoleAssignment {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Scope,

    [Parameter(Mandatory = $true)]
    [string]$PrincipalObjectId,

    [Parameter(Mandatory = $true)]
    [string]$RoleDefinitionGuid,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [ValidateSet('ServicePrincipal', 'User', 'Group')]
    [string]$PrincipalType = 'ServicePrincipal'
  )

  $roleDefinitionId = if ($Scope -like '/providers/Microsoft.Management/managementGroups/*') {
    "/providers/Microsoft.Authorization/roleDefinitions/$RoleDefinitionGuid"
  }
  else {
    "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$RoleDefinitionGuid"
  }

  $existingPath = "$Scope/providers/Microsoft.Authorization/roleAssignments?`$filter=atScope()&api-version=2022-04-01"
  $existingResponse = Invoke-AzRestMethod -Method GET -Path $existingPath
  if ($existingResponse.StatusCode -eq 200) {
    $existingPayload = $existingResponse.Content | ConvertFrom-Json
    $existingMatch = @($existingPayload.value | Where-Object {
        $_.properties.principalId -eq $PrincipalObjectId -and $_.properties.roleDefinitionId -eq $roleDefinitionId
      }) | Select-Object -First 1
    if ($existingMatch) {
      return $null
    }
  }

  $assignmentName = [guid]::NewGuid().ToString()
  $createPath = "$Scope/providers/Microsoft.Authorization/roleAssignments/${assignmentName}?api-version=2022-04-01"
  $body = @{
    properties = @{
      roleDefinitionId = $roleDefinitionId
      principalId      = $PrincipalObjectId
      principalType    = $PrincipalType
    }
  } | ConvertTo-Json -Depth 10

  $createResponse = Invoke-AzRestMethod -Method PUT -Path $createPath -Payload $body
  if ($createResponse.StatusCode -in @(200, 201)) {
    $payload = $createResponse.Content | ConvertFrom-Json
    if ($payload -and $payload.id) {
      return $payload.id
    }
  }

  if ($createResponse.StatusCode -eq 409) {
    return $null
  }

  throw "Role assignment failed for role '$RoleDefinitionGuid' at scope '$Scope'. HTTP $($createResponse.StatusCode): $($createResponse.Content)"
}

function Push-RepositoryFiles {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryUrl,

    [Parameter(Mandatory = $true)]
    [string]$Branch,

    [Parameter(Mandatory = $true)]
    [string]$BearerToken,

    [Parameter(Mandatory = $true)]
    [object[]]$Files
  )

  $tempPath = Join-Path -Path $env:TEMP -ChildPath ("maester-ado-{0}" -f ([guid]::NewGuid().ToString('N')))
  New-Item -Path $tempPath -ItemType Directory -Force | Out-Null

  $header = "http.extraheader=AUTHORIZATION: bearer $BearerToken"

  try {
    & git -c $header clone $RepositoryUrl $tempPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw "git clone failed for '$RepositoryUrl'."
    }

    & git -C $tempPath checkout -B $Branch | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw "git checkout -B $Branch failed."
    }

    foreach ($file in $Files) {
      $targetPath = Join-Path -Path $tempPath -ChildPath $file.Path
      $targetDir = Split-Path -Path $targetPath -Parent
      if (-not (Test-Path -Path $targetDir)) {
        New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
      }

      Set-Content -Path $targetPath -Value $file.Content -Encoding utf8
    }

    & git -C $tempPath add --all | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw 'git add failed.'
    }

    $statusOutput = & git -C $tempPath status --porcelain
    if ($LASTEXITCODE -ne 0) {
      throw 'git status failed.'
    }

    if (-not $statusOutput) {
      return [pscustomobject]@{
        Pushed     = $false
        Changed    = $false
        Branch     = $Branch
        Repository = $RepositoryUrl
      }
    }

    & git -C $tempPath -c user.name='maester-setup' -c user.email='maester-setup@local' commit -m 'chore: bootstrap maester pipeline files' | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw 'git commit failed.'
    }

    & git -C $tempPath -c $header push origin $Branch | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw "git push origin $Branch failed."
    }

    return [pscustomobject]@{
      Pushed     = $true
      Changed    = $true
      Branch     = $Branch
      Repository = $RepositoryUrl
    }
  }
  finally {
    if (Test-Path -Path $tempPath) {
      Remove-Item -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot

Import-Module (Join-Path $PSScriptRoot '..\..\shared\scripts\Maester-SetupHelpers.psm1') -Force
Import-Module Az.Accounts -Force

$adopsInstallMessage = "PowerShell module 'ADOPS' is required to configure Azure DevOps. Install now to continue postprovision setup."
if (-not (Test-ModuleAvailable -ModuleName 'ADOPS' -InstallMessage $adopsInstallMessage)) {
  throw "PowerShell module 'ADOPS' is required for postprovision setup. Install it with: Install-Module ADOPS -Scope CurrentUser -Force -AllowClobber"
}

$envLines = @{}
try {
  $envLines = (& azd env get-values --output json 2>$null | ConvertFrom-Json -AsHashtable)
}
catch {
  $envLines = @{}
}

if (-not $SubscriptionId) {
  $SubscriptionId = if ($env:AZURE_SUBSCRIPTION_ID) { $env:AZURE_SUBSCRIPTION_ID } else { Get-EnvValue -Lines $envLines -Name 'AZURE_SUBSCRIPTION_ID' }
}
if (-not $TenantId) {
  $TenantId = if ($env:AZURE_TENANT_ID) { $env:AZURE_TENANT_ID } else { Get-EnvValue -Lines $envLines -Name 'AZURE_TENANT_ID' }
}
if (-not $EnvironmentName) {
  $EnvironmentName = if ($env:AZURE_ENV_NAME) { $env:AZURE_ENV_NAME } else { Get-EnvValue -Lines $envLines -Name 'AZURE_ENV_NAME' }
  if ([string]::IsNullOrWhiteSpace($EnvironmentName)) {
    $EnvironmentName = 'dev'
  }
}
if (-not $ResourceGroupName) {
  $ResourceGroupName = if ($env:AZURE_RESOURCE_GROUP) { $env:AZURE_RESOURCE_GROUP } else { Get-EnvValue -Lines $envLines -Name 'AZURE_RESOURCE_GROUP' }
  if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
    $ResourceGroupName = "rg-$EnvironmentName"
  }
}
if (-not $PSBoundParameters.ContainsKey('PermissionProfile')) {
  $permissionProfileValue = if ($env:PERMISSION_PROFILE) { $env:PERMISSION_PROFILE } else { Get-EnvValue -Lines $envLines -Name 'PERMISSION_PROFILE' }
  if (-not [string]::IsNullOrWhiteSpace($permissionProfileValue)) {
    $PermissionProfile = $permissionProfileValue
  }
}

if (-not $PSBoundParameters.ContainsKey('IncludeExchange')) {
  $includeExchangeValue = if ($env:INCLUDE_EXCHANGE) { $env:INCLUDE_EXCHANGE } else { Get-EnvValue -Lines $envLines -Name 'INCLUDE_EXCHANGE' }
  $IncludeExchange = ConvertTo-BoolOrDefault -Value $includeExchangeValue -Default $false
}
if (-not $PSBoundParameters.ContainsKey('IncludeTeams')) {
  $includeTeamsValue = if ($env:INCLUDE_TEAMS) { $env:INCLUDE_TEAMS } else { Get-EnvValue -Lines $envLines -Name 'INCLUDE_TEAMS' }
  $IncludeTeams = ConvertTo-BoolOrDefault -Value $includeTeamsValue -Default $false
}
if (-not $PSBoundParameters.ContainsKey('IncludeAzure')) {
  $includeAzureValue = if ($env:INCLUDE_AZURE) { $env:INCLUDE_AZURE } else { Get-EnvValue -Lines $envLines -Name 'INCLUDE_AZURE' }
  $IncludeAzure = ConvertTo-BoolOrDefault -Value $includeAzureValue -Default $false
}

if (-not $PSBoundParameters.ContainsKey('AzureScopes')) {
  $rawScopes = if ($env:AZURE_RBAC_SCOPES) { $env:AZURE_RBAC_SCOPES } else { Get-EnvValue -Lines $envLines -Name 'AZURE_RBAC_SCOPES' }
  if ($rawScopes) {
    $AzureScopes = @($rawScopes -split ';' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  }
}
if ($IncludeAzure -and (-not $AzureScopes -or $AzureScopes.Count -eq 0)) {
  $AzureScopes = @("/subscriptions/$SubscriptionId")
}

if (-not $SecurityGroupObjectId) {
  if ($env:SECURITY_GROUP_OBJECT_ID) {
    $SecurityGroupObjectId = $env:SECURITY_GROUP_OBJECT_ID
  }
  elseif ($env:EASY_AUTH_SECURITY_GROUP_OBJECT_ID) {
    $SecurityGroupObjectId = $env:EASY_AUTH_SECURITY_GROUP_OBJECT_ID
  }
  else {
    $SecurityGroupObjectId = Get-EnvValue -Lines $envLines -Name 'SECURITY_GROUP_OBJECT_ID'
    if (-not $SecurityGroupObjectId) {
      $SecurityGroupObjectId = Get-EnvValue -Lines $envLines -Name 'EASY_AUTH_SECURITY_GROUP_OBJECT_ID'
    }
  }
}
if (-not $SecurityGroupDisplayName) {
  if ($env:SECURITY_GROUP_DISPLAY_NAME) {
    $SecurityGroupDisplayName = $env:SECURITY_GROUP_DISPLAY_NAME
  }
  else {
    $SecurityGroupDisplayName = Get-EnvValue -Lines $envLines -Name 'SECURITY_GROUP_DISPLAY_NAME'
  }
}

if (-not $AdoOrganization) {
  $AdoOrganization = if ($env:AZDO_ORGANIZATION) { $env:AZDO_ORGANIZATION } else { Get-EnvValue -Lines $envLines -Name 'AZDO_ORGANIZATION' }
}
if (-not $AdoProject) {
  $AdoProject = if ($env:AZDO_PROJECT) { $env:AZDO_PROJECT } else { Get-EnvValue -Lines $envLines -Name 'AZDO_PROJECT' }
}
if (-not $AdoRepositoryName) {
  $AdoRepositoryName = if ($env:AZDO_REPOSITORY) { $env:AZDO_REPOSITORY } else { Get-EnvValue -Lines $envLines -Name 'AZDO_REPOSITORY' }
}
if (-not $AdoPipelineName) {
  $AdoPipelineName = if ($env:AZDO_PIPELINE_NAME) { $env:AZDO_PIPELINE_NAME } else { Get-EnvValue -Lines $envLines -Name 'AZDO_PIPELINE_NAME' }
}
if (-not $AdoServiceConnectionName) {
  $AdoServiceConnectionName = if ($env:AZDO_SERVICE_CONNECTION_NAME) { $env:AZDO_SERVICE_CONNECTION_NAME } else { Get-EnvValue -Lines $envLines -Name 'AZDO_SERVICE_CONNECTION_NAME' }
}
if (-not $PipelineYamlPath) {
  $PipelineYamlPath = if ($env:AZDO_PIPELINE_YAML_PATH) { $env:AZDO_PIPELINE_YAML_PATH } else { Get-EnvValue -Lines $envLines -Name 'AZDO_PIPELINE_YAML_PATH' }
}
if (-not $DefaultBranch) {
  $DefaultBranch = if ($env:AZDO_DEFAULT_BRANCH) { $env:AZDO_DEFAULT_BRANCH } else { Get-EnvValue -Lines $envLines -Name 'AZDO_DEFAULT_BRANCH' }
}
if (-not $ScheduleCron) {
  $ScheduleCron = if ($env:AZDO_SCHEDULE_CRON) { $env:AZDO_SCHEDULE_CRON } else { Get-EnvValue -Lines $envLines -Name 'AZDO_SCHEDULE_CRON' }
}

if (-not $PSBoundParameters.ContainsKey('CreateRepositoryIfMissing')) {
  $createRepoIfMissingValue = if ($env:AZDO_CREATE_REPO_IF_MISSING) { $env:AZDO_CREATE_REPO_IF_MISSING } else { Get-EnvValue -Lines $envLines -Name 'AZDO_CREATE_REPO_IF_MISSING' }
  $CreateRepositoryIfMissing = ConvertTo-BoolOrDefault -Value $createRepoIfMissingValue -Default $true
}
if (-not $PSBoundParameters.ContainsKey('PushPipelineFiles')) {
  $pushPipelineFilesValue = if ($env:AZDO_PUSH_PIPELINE_FILES) { $env:AZDO_PUSH_PIPELINE_FILES } else { Get-EnvValue -Lines $envLines -Name 'AZDO_PUSH_PIPELINE_FILES' }
  $PushPipelineFiles = ConvertTo-BoolOrDefault -Value $pushPipelineFilesValue -Default $true
}
if (-not $PSBoundParameters.ContainsKey('ValidatePipelineRun')) {
  $validatePipelineRunValue = if ($env:AZDO_VALIDATE_PIPELINE_RUN) { $env:AZDO_VALIDATE_PIPELINE_RUN } else { Get-EnvValue -Lines $envLines -Name 'AZDO_VALIDATE_PIPELINE_RUN' }
  $ValidatePipelineRun = ConvertTo-BoolOrDefault -Value $validatePipelineRunValue -Default $true
}
if (-not $PSBoundParameters.ContainsKey('FailOnTestFailures')) {
  $failOnTestFailuresValue = if ($env:AZDO_FAIL_ON_TEST_FAILURES) { $env:AZDO_FAIL_ON_TEST_FAILURES } else { Get-EnvValue -Lines $envLines -Name 'AZDO_FAIL_ON_TEST_FAILURES' }
  $FailOnTestFailures = ConvertTo-BoolOrDefault -Value $failOnTestFailuresValue -Default $true
}

$SubscriptionId = Test-RequiredValue -Value $SubscriptionId -Name 'SubscriptionId'
$AdoOrganization = Test-RequiredValue -Value $AdoOrganization -Name 'AdoOrganization'
$AdoProject = Test-RequiredValue -Value $AdoProject -Name 'AdoProject'
$AdoRepositoryName = Test-RequiredValue -Value $AdoRepositoryName -Name 'AdoRepositoryName'
$AdoPipelineName = Test-RequiredValue -Value $AdoPipelineName -Name 'AdoPipelineName'
$AdoServiceConnectionName = Test-RequiredValue -Value $AdoServiceConnectionName -Name 'AdoServiceConnectionName'
if ([string]::IsNullOrWhiteSpace($PipelineYamlPath)) {
  $PipelineYamlPath = '/azure-pipelines.yml'
}
if ([string]::IsNullOrWhiteSpace($DefaultBranch)) {
  $DefaultBranch = 'main'
}
if ([string]::IsNullOrWhiteSpace($ScheduleCron)) {
  $ScheduleCron = '0 0 * * 0'
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

$currentContext = Get-AzContext
if (-not $TenantId -and $currentContext -and $currentContext.Tenant) {
  $TenantId = $currentContext.Tenant.Id
}

$subscriptionName = az account show --query name -o tsv
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($subscriptionName)) {
  if ($currentContext -and $currentContext.Subscription) {
    $subscriptionName = $currentContext.Subscription.Name
  }
  else {
    throw 'Could not determine subscription name from current Azure context.'
  }
}

Write-Host 'Connecting to Azure DevOps with ADOPS and OAuth token...'
$devOpsTokenResponse = Get-AzAccessToken -ResourceUrl '499b84ac-1321-427f-aa17-267ca6975798'
$devOpsToken = ConvertTo-PlainTextToken -TokenValue $devOpsTokenResponse.Token
Connect-ADOPS -Organization $AdoOrganization -OAuthToken $devOpsToken -SkipVerification | Out-Null

$projectInfo = Get-ADOPSProject -Name $AdoProject -Organization $AdoOrganization
if (-not $projectInfo) {
  throw "Azure DevOps project '$AdoProject' was not found in organization '$AdoOrganization'."
}

$repository = $null
try {
  $repository = Get-ADOPSRepository -Project $AdoProject -Repository $AdoRepositoryName -Organization $AdoOrganization -ErrorAction Stop
}
catch {
  $repository = $null
}

if (-not $repository) {
  if (-not $CreateRepositoryIfMissing) {
    throw "Azure DevOps repository '$AdoRepositoryName' was not found and CreateRepositoryIfMissing=false."
  }

  Write-Host "Creating Azure DevOps repository '$AdoRepositoryName'..."
  $repository = New-ADOPSRepository -Name $AdoRepositoryName -Project $AdoProject -Organization $AdoOrganization
}

$repositoryId = [string](Get-OptionalPropertyValue -InputObject $repository -PropertyNames @('id'))
$repositoryRemoteUrl = [string](Get-OptionalPropertyValue -InputObject $repository -PropertyNames @('remoteUrl'))
$repositoryWebUrl = [string](Get-OptionalPropertyValue -InputObject $repository -PropertyNames @('webUrl'))
$repositoryUrl = if (-not [string]::IsNullOrWhiteSpace($repositoryRemoteUrl)) { $repositoryRemoteUrl } else { $repositoryWebUrl }
if ([string]::IsNullOrWhiteSpace($repositoryId)) {
  throw "Could not determine repository id for '$AdoRepositoryName'."
}
if ([string]::IsNullOrWhiteSpace($repositoryUrl)) {
  throw "Could not determine clone URL for repository '$AdoRepositoryName'."
}

$serviceConnection = $null
try {
  $serviceConnection = Get-ADOPSServiceConnection -Project $AdoProject -Name $AdoServiceConnectionName -Organization $AdoOrganization -IncludeFailed -ErrorAction Stop
}
catch {
  $serviceConnection = $null
}

$serviceConnectionScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
if (-not $serviceConnection) {
  Write-Host "Creating Azure DevOps service connection '$AdoServiceConnectionName' using workload identity federation..."
  $serviceConnection = New-ADOPSServiceConnection `
    -Organization $AdoOrganization `
    -Project $AdoProject `
    -ConnectionName $AdoServiceConnectionName `
    -TenantId $TenantId `
    -SubscriptionName $subscriptionName `
    -SubscriptionId $SubscriptionId `
    -WorkloadIdentityFederation `
    -CreationMode Manual `
    -AzureScope $serviceConnectionScope `
    -Description "Maester federated identity service connection for environment '$EnvironmentName'"
}

$serviceConnectionId = [string](Get-OptionalPropertyValue -InputObject $serviceConnection -PropertyNames @('id'))
if ([string]::IsNullOrWhiteSpace($serviceConnectionId)) {
  throw "Could not determine service connection id for '$AdoServiceConnectionName'."
}

$serviceConnectionAuthorization = Get-OptionalPropertyValue -InputObject $serviceConnection -PropertyNames @('authorization')
$serviceConnectionParameters = Get-OptionalPropertyValue -InputObject $serviceConnectionAuthorization -PropertyNames @('parameters')
$workloadIssuer = [string](Get-OptionalPropertyValue -InputObject $serviceConnectionParameters -PropertyNames @('workloadIdentityFederationIssuer'))
$workloadSubject = [string](Get-OptionalPropertyValue -InputObject $serviceConnectionParameters -PropertyNames @('workloadIdentityFederationSubject'))
if ([string]::IsNullOrWhiteSpace($workloadIssuer) -or [string]::IsNullOrWhiteSpace($workloadSubject)) {
  $parameterKeys = @()
  if ($serviceConnectionParameters) {
    $parameterKeys = @($serviceConnectionParameters.PSObject.Properties.Name)
  }
  $availableKeys = if ($parameterKeys.Count -gt 0) { $parameterKeys -join ', ' } else { '<none>' }
  throw "Service connection '$AdoServiceConnectionName' did not return workload identity issuer/subject values. Available authorization.parameters keys: $availableKeys"
}

$workloadIdentityDisplayName = "sc-app-maester-$($EnvironmentName.ToLower())"
$appRegistrationAppId = [string](Get-OptionalPropertyValue -InputObject $serviceConnectionParameters -PropertyNames @('serviceprincipalid', 'servicePrincipalId', 'servicePrincipalID'))
$aadApplication = $null
if (-not [string]::IsNullOrWhiteSpace($appRegistrationAppId)) {
  try {
    $appByIdResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$appRegistrationAppId'&`$select=id,appId,displayName"
    $appByIdMatches = @($appByIdResponse.value)
    if ($appByIdMatches.Count -gt 0) {
      $appById = $appByIdMatches[0]
      $aadApplication = [pscustomobject]@{
        Id          = $appById.id
        AppId       = $appById.appId
        DisplayName = $appById.displayName
      }
    }
  }
  catch {
    $aadApplication = $null
  }
}

if ($aadApplication -and -not [string]::IsNullOrWhiteSpace($aadApplication.DisplayName) -and $aadApplication.DisplayName -ne $workloadIdentityDisplayName) {
  Write-Warning "Service connection currently references app '$($aadApplication.DisplayName)' ($($aadApplication.AppId)). Expected '$workloadIdentityDisplayName'. Using environment-specific app registration instead."
  $aadApplication = $null
}

if (-not $aadApplication) {
  $existingApps = @()
  try {
    $displayNameFilterValue = $workloadIdentityDisplayName -replace "'", "''"
    $existingAppsResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$displayNameFilterValue'&`$select=id,appId,displayName"
    $existingApps = @($existingAppsResponse.value)
  }
  catch {
    $existingApps = @()
  }

  if ($existingApps.Count -gt 0) {
    $existingApp = $existingApps[0]
    $aadApplication = [pscustomobject]@{
      Id          = $existingApp.id
      AppId       = $existingApp.appId
      DisplayName = $existingApp.displayName
    }
  }
}

if (-not $aadApplication) {
  Write-Host "Creating Entra application registration '$workloadIdentityDisplayName'..."
  $createAppBody = @{
    displayName    = $workloadIdentityDisplayName
    signInAudience = 'AzureADMyOrg'
  } | ConvertTo-Json -Depth 10

  $createdApp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body $createAppBody -ContentType 'application/json'
  $aadApplication = [pscustomobject]@{
    Id          = $createdApp.id
    AppId       = $createdApp.appId
    DisplayName = $createdApp.displayName
  }
}

$servicePrincipal = $null
try {
  $spResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$($aadApplication.AppId)'&`$select=id,appId,displayName"
  $spMatches = @($spResponse.value)
  if ($spMatches.Count -gt 0) {
    $existingSp = $spMatches[0]
    $servicePrincipal = [pscustomobject]@{
      Id          = $existingSp.id
      AppId       = $existingSp.appId
      DisplayName = $existingSp.displayName
    }
  }
}
catch {
  $servicePrincipal = $null
}

if (-not $servicePrincipal) {
  Write-Host "Creating service principal for appId '$($aadApplication.AppId)'..."
  $createSpBody = @{ appId = $aadApplication.AppId } | ConvertTo-Json -Depth 10
  $createdSp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Body $createSpBody -ContentType 'application/json'
  $servicePrincipal = [pscustomobject]@{
    Id          = $createdSp.id
    AppId       = $createdSp.appId
    DisplayName = $createdSp.displayName
  }
}

$federatedCredentials = @()
try {
  $federatedResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications/$($aadApplication.Id)/federatedIdentityCredentials?`$select=id,name,issuer,subject"
  $federatedCredentials = @($federatedResponse.value)
}
catch {
  $federatedCredentials = @()
}

$matchingFederatedCredential = @($federatedCredentials | Where-Object { $_.issuer -eq $workloadIssuer -and $_.subject -eq $workloadSubject }) | Select-Object -First 1
if (-not $matchingFederatedCredential) {
  Write-Host 'Creating Entra federated credential for Azure DevOps service connection...'
  $federatedCredentialName = "ado-$($EnvironmentName.ToLower())"
  $federatedCredentialBody = @{
    name        = $federatedCredentialName
    issuer      = $workloadIssuer
    subject     = $workloadSubject
    audiences   = @('api://AzureADTokenExchange')
    description = "Azure DevOps federation for '$AdoOrganization/$AdoProject'"
  } | ConvertTo-Json -Depth 10

  $null = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$($aadApplication.Id)/federatedIdentityCredentials" -Body $federatedCredentialBody -ContentType 'application/json'
}
Write-Host 'Finalizing Azure DevOps service connection with Entra app details...'
$serviceConnection = Set-ADOPSServiceConnection `
  -Organization $AdoOrganization `
  -Project $AdoProject `
  -ServiceEndpointId $serviceConnectionId `
  -ConnectionName $AdoServiceConnectionName `
  -TenantId $TenantId `
  -SubscriptionName $subscriptionName `
  -SubscriptionId $SubscriptionId `
  -ServicePrincipalId $aadApplication.AppId `
  -WorkloadIdentityFederationIssuer $workloadIssuer `
  -WorkloadIdentityFederationSubject $workloadSubject `
  -Description "Maester federated identity service connection for environment '$EnvironmentName'"

$serviceConnectionAuthorized = Test-AdoServiceConnectionAuthorizedForPipelines `
  -Organization $AdoOrganization `
  -Project $AdoProject `
  -ServiceConnectionId $serviceConnectionId `
  -ServiceConnectionName $AdoServiceConnectionName

Set-AzdEnvValue -Name 'AZDO_SERVICE_CONNECTION_AUTHORIZED' -Value $serviceConnectionAuthorized.ToString().ToLower()
Set-AzdEnvValue -Name 'AZDO_ORGANIZATION' -Value $AdoOrganization
Set-AzdEnvValue -Name 'AZDO_PROJECT' -Value $AdoProject
Set-AzdEnvValue -Name 'AZDO_REPOSITORY' -Value $AdoRepositoryName
Set-AzdEnvValue -Name 'AZDO_REPOSITORY_ID' -Value $repositoryId
Set-AzdEnvValue -Name 'AZDO_REPOSITORY_URL' -Value $repositoryUrl
Set-AzdEnvValue -Name 'AZDO_SERVICE_CONNECTION_NAME' -Value $AdoServiceConnectionName
Set-AzdEnvValue -Name 'AZDO_SERVICE_CONNECTION_ID' -Value $serviceConnectionId
Set-AzdEnvValue -Name 'AZDO_WORKLOAD_APP_ID' -Value $aadApplication.AppId
Set-AzdEnvValue -Name 'AZDO_WORKLOAD_APP_OBJECT_ID' -Value $aadApplication.Id
Set-AzdEnvValue -Name 'AZDO_WORKLOAD_SERVICE_PRINCIPAL_OBJECT_ID' -Value $servicePrincipal.Id
Set-AzdEnvValue -Name 'AZDO_WORKLOAD_IDENTITY_DISPLAY_NAME' -Value $workloadIdentityDisplayName

$resourcesPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/resources?api-version=2021-04-01"
$resourcesPayload = (Invoke-AzRestMethod -Method GET -Path $resourcesPath).Content | ConvertFrom-Json
$resources = @($resourcesPayload.value)

$storageResource = $resources | Where-Object { $_.type -eq 'Microsoft.Storage/storageAccounts' } | Select-Object -First 1
if (-not $storageResource) {
  throw "Storage account was not found in resource group '$ResourceGroupName'."
}
$webAppResource = $resources | Where-Object { $_.type -eq 'Microsoft.Web/sites' } | Select-Object -First 1

$baseRoleAssignmentIds = @()

$resourceGroupScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
$readerRoleId = Test-AzureRoleAssignment -Scope $resourceGroupScope -PrincipalObjectId $servicePrincipal.Id -RoleDefinitionGuid 'acdd72a7-3385-48ef-bd42-f606fba81ae7' -SubscriptionId $SubscriptionId
if ($readerRoleId) {
  $baseRoleAssignmentIds += $readerRoleId
  Write-Host "Assigned Reader on resource group '$ResourceGroupName' to workload identity."
}

$storageBlobContributorRoleId = Test-AzureRoleAssignment -Scope $storageResource.id -PrincipalObjectId $servicePrincipal.Id -RoleDefinitionGuid 'ba92f5b4-2d11-453d-a403-e96b0029c9fe' -SubscriptionId $SubscriptionId
if ($storageBlobContributorRoleId) {
  $baseRoleAssignmentIds += $storageBlobContributorRoleId
  Write-Host "Assigned Storage Blob Data Contributor on '$($storageResource.name)' to workload identity."
}

if ($webAppResource) {
  $websiteContributorRoleId = Test-AzureRoleAssignment -Scope $webAppResource.id -PrincipalObjectId $servicePrincipal.Id -RoleDefinitionGuid 'de139f84-1756-47ae-9be6-808fbbe84772' -SubscriptionId $SubscriptionId
  if ($websiteContributorRoleId) {
    $baseRoleAssignmentIds += $websiteContributorRoleId
    Write-Host "Assigned Website Contributor on '$($webAppResource.name)' to workload identity."
  }
}

Set-AzdEnvJsonArray -Name 'AZDO_BASE_ROLE_ASSIGNMENT_IDS' -Values @($baseRoleAssignmentIds)

Write-Host 'Granting Microsoft Graph permissions for Maester...'
$mailRecipientForGraph = if ($env:MAIL_RECIPIENT) { $env:MAIL_RECIPIENT.Trim() } else { '' }
$includeMailSend = -not [string]::IsNullOrWhiteSpace($mailRecipientForGraph)
& (Join-Path $PSScriptRoot '..\..\shared\scripts\Grant-MaesterGraphPermissions.ps1') `
  -TenantId $TenantId `
  -PrincipalObjectId $servicePrincipal.Id `
  -PermissionProfile $PermissionProfile `
  -IncludeMailSend $includeMailSend

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
    Invoke-GraphAuthProbe -TenantId $TenantId -Scopes $scopes
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

    $newAssignmentId = Grant-ServicePrincipalAppRoleAssignment -PrincipalObjectId $servicePrincipal.Id -ResourceAppId $exchangeResourceAppId -AppRoleId $exchangeManageAsAppRoleId
    if ($newAssignmentId) {
      $exoAppRoleAssignmentIds += $newAssignmentId
      Write-Host 'Assigned Exchange.ManageAsApp to the Azure DevOps workload identity.'
    }
    else {
      Write-Host 'Exchange.ManageAsApp is already assigned to the Azure DevOps workload identity.'
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
    $exoServicePrincipalDisplayName = $servicePrincipal.DisplayName
    $installMsg = "Exchange Online PowerShell is required to grant the workload identity the Exchange RBAC role 'View-Only Configuration'."
    if (-not (Test-ModuleAvailable -ModuleName 'ExchangeOnlineManagement' -InstallMessage $installMsg)) {
      throw 'ExchangeOnlineManagement module is not available. Install it and rerun setup with -IncludeExchange.'
    }

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

    $existingExchangeSp = $null
    foreach ($identityValue in @($servicePrincipal.DisplayName, $servicePrincipal.AppId, $servicePrincipal.Id)) {
      if ([string]::IsNullOrWhiteSpace([string]$identityValue)) {
        continue
      }

      try {
        $candidate = Get-ServicePrincipal -Identity $identityValue -ErrorAction SilentlyContinue
        $existingExchangeSp = @($candidate) | Select-Object -First 1
      }
      catch {
        $existingExchangeSp = $null
      }

      if ($existingExchangeSp) {
        break
      }
    }

    if ($existingExchangeSp -and -not [string]::IsNullOrWhiteSpace([string]$existingExchangeSp.DisplayName)) {
      $exoServicePrincipalDisplayName = [string]$existingExchangeSp.DisplayName
      Write-Host "Exchange service principal already exists as '$exoServicePrincipalDisplayName'."
    }

    try {
      if (-not $existingExchangeSp) {
        New-ServicePrincipal -AppId $servicePrincipal.AppId -ObjectId $servicePrincipal.Id -DisplayName $servicePrincipal.DisplayName | Out-Null
        Write-Host "Created/linked Exchange service principal for '$($servicePrincipal.DisplayName)'."
      }
    }
    catch {
      $message = $_.Exception.Message
      if ($message -match 'already exists' -or $message -match 'already used') {
        Write-Host "Exchange service principal mapping already exists for '$($servicePrincipal.DisplayName)'."
      }
      else {
        throw
      }
    }

    try {
      $roleAssignment = New-ManagementRoleAssignment -Role 'View-Only Configuration' -App $exoServicePrincipalDisplayName -ErrorAction Stop
      if ($roleAssignment -and $roleAssignment.Identity) {
        Write-Host "Assigned Exchange RBAC role 'View-Only Configuration' to '$exoServicePrincipalDisplayName'."
      }
      else {
        Write-Host "Ensured Exchange RBAC role 'View-Only Configuration' is assigned to '$exoServicePrincipalDisplayName'."
      }
      $exchangeRbacOk = $true
    }
    catch {
      $message = $_.Exception.Message
      if ($message -match 'already exists') {
        Write-Host "Exchange RBAC role 'View-Only Configuration' is already assigned to '$exoServicePrincipalDisplayName'."
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
    $teamsRoleCandidates = @(
      'Teams Administrator',
      'Teams Reader'
    )

    $teamsRoleConfigured = $false
    $selectedTeamsRole = $null
    $lastTeamsRoleError = $null
    foreach ($candidateRole in $teamsRoleCandidates) {
      try {
        $newTeamsRoleAssignmentId = Test-DirectoryRoleAssignment -PrincipalObjectId $servicePrincipal.Id -RoleDisplayName $candidateRole
        if ($newTeamsRoleAssignmentId) {
          $teamsRoleAssignmentIds += $newTeamsRoleAssignmentId
          Write-Host "Assigned Entra directory role '$candidateRole' to the Azure DevOps workload identity."
        }
        else {
          Write-Host "Entra directory role '$candidateRole' is already assigned to the Azure DevOps workload identity."
        }

        $selectedTeamsRole = $candidateRole
        $teamsRoleConfigured = $true
        break
      }
      catch {
        $lastTeamsRoleError = $_
        Write-Warning ("Teams role assignment attempt failed for role '{0}': {1}" -f $candidateRole, $_.Exception.Message)
      }
    }

    if (-not $teamsRoleConfigured) {
      if ($lastTeamsRoleError) {
        throw $lastTeamsRoleError
      }
      throw 'Unable to assign a Teams directory role to the Azure DevOps workload identity.'
    }

    if ($selectedTeamsRole) {
      Set-AzdEnvValue -Name 'TEAMS_DIRECTORY_ROLE' -Value $selectedTeamsRole
    }

    $teamsSetupStatus = 'configured'
  }
  catch {
    $action = Resolve-StepFailureAction -StepName 'Teams directory role assignment' -Message $_.Exception.Message
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
      $newAzureAssignmentId = Test-AzureReaderRoleAssignment -Scope $scope -PrincipalObjectId $servicePrincipal.Id -SubscriptionId $SubscriptionId
      if ($newAzureAssignmentId) {
        $azureRoleAssignmentIds += $newAzureAssignmentId
        Write-Host "Granted Azure RBAC Reader to Azure DevOps workload identity at scope: $scope"
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
$includeWebApp = [bool]$webAppResource
if ($includeWebApp) {
  $securityGroupSource = 'parameter'
  if (-not $PSBoundParameters.ContainsKey('SecurityGroupObjectId') -and -not $PSBoundParameters.ContainsKey('SecurityGroupDisplayName')) {
    if ($env:SECURITY_GROUP_OBJECT_ID -or $env:EASY_AUTH_SECURITY_GROUP_OBJECT_ID) {
      $securityGroupSource = 'environment'
    }
  }

  if (-not $SecurityGroupObjectId -and -not [string]::IsNullOrWhiteSpace($SecurityGroupDisplayName)) {
    Invoke-GraphAuthProbe -TenantId $TenantId -Scopes 'Group.Read.All','Directory.Read.All'

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
      throw "Multiple Entra security groups matched '$SecurityGroupDisplayName'. Provide SecurityGroupObjectId to avoid ambiguity."
    }
  }

  if (-not $SecurityGroupObjectId) {
    throw 'SecurityGroupObjectId is required to configure Easy Auth when includeWebApp=true. Provide -SecurityGroupObjectId, set SECURITY_GROUP_OBJECT_ID, or set EASY_AUTH_SECURITY_GROUP_OBJECT_ID.'
  }

  Invoke-GraphAuthProbe -TenantId $TenantId -Scopes 'Application.ReadWrite.All','Directory.Read.All','DelegatedPermissionGrant.ReadWrite.All'

  $webAppName = $webAppResource.name
  $webAppHostName = $null

  $webAppProperties = Get-OptionalPropertyValue -InputObject $webAppResource -PropertyNames @('properties')
  if ($webAppProperties) {
    $webAppHostName = [string](Get-OptionalPropertyValue -InputObject $webAppProperties -PropertyNames @('defaultHostName'))
  }

  if ([string]::IsNullOrWhiteSpace($webAppHostName)) {
    $webAppDetailPath = "$($webAppResource.id)?api-version=2023-12-01"
    $webAppDetailResponse = Invoke-AzRestMethod -Method GET -Path $webAppDetailPath
    if ($webAppDetailResponse.StatusCode -in @(200, 201) -and -not [string]::IsNullOrWhiteSpace($webAppDetailResponse.Content)) {
      $webAppDetail = $webAppDetailResponse.Content | ConvertFrom-Json
      if ($webAppDetail -and $webAppDetail.properties -and $webAppDetail.properties.defaultHostName) {
        $webAppHostName = [string]$webAppDetail.properties.defaultHostName
      }
    }
  }

  if ([string]::IsNullOrWhiteSpace($webAppHostName)) {
    throw "Could not determine default host name for Web App '$webAppName'."
  }

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

  Set-AzdEnvValue -Name 'EASY_AUTH_ENTRA_APP_OBJECT_ID' -Value $aadApp.id
  Set-AzdEnvValue -Name 'EASY_AUTH_ENTRA_APP_CLIENT_ID' -Value $aadApp.appId
  Set-AzdEnvValue -Name 'EASY_AUTH_ENTRA_APP_DISPLAY_NAME' -Value $aadApp.displayName

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

  $authPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$webAppName/config/authsettingsV2?api-version=2023-12-01"
  Invoke-AzRestMethod -Method PUT -Path $authPath -Payload $authPayload | Out-Null

  Write-Host "Configured Easy Auth for Web App '$webAppName'."
  Write-Host "Easy Auth security group: $SecurityGroupObjectId (source: $securityGroupSource)"
}
$pipelineTemplatePath = Join-Path -Path $projectRoot -ChildPath 'pipelines/template-maester.yml'
if (-not (Test-Path -Path $pipelineTemplatePath)) {
  throw "Pipeline template was not found: $pipelineTemplatePath"
}

$pipelineRepoPath = $PipelineYamlPath.Trim()
if ([string]::IsNullOrWhiteSpace($pipelineRepoPath)) {
  $pipelineRepoPath = '/azure-pipelines.yml'
}
$pipelineRepoPath = $pipelineRepoPath.TrimStart('/')

$templateContent = Get-Content -Path $pipelineTemplatePath -Raw
$runnerScriptContent = Get-Content -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-MaesterAzureDevOpsRun.ps1') -Raw

$replacementMap = @{
  '__SERVICE_CONNECTION__' = $AdoServiceConnectionName
  '__DEFAULT_BRANCH__' = $DefaultBranch
  '__SCHEDULE_CRON__' = $ScheduleCron
  '__INCLUDE_EXCHANGE__' = ([bool]$IncludeExchange).ToString().ToLower()
  '__INCLUDE_TEAMS__' = ([bool]$IncludeTeams).ToString().ToLower()
  '__INCLUDE_AZURE__' = ([bool]$IncludeAzure).ToString().ToLower()
  '__INCLUDE_WEB_APP__' = ([bool]$includeWebApp).ToString().ToLower()
  '__STORAGE_ACCOUNT_NAME__' = $storageResource.name
  '__WEB_APP_NAME__' = $(if ($webAppResource) { $webAppResource.name } else { '' })
  '__WEB_APP_RESOURCE_GROUP__' = $(if ($webAppResource) { $ResourceGroupName } else { '' })
  '__TENANT_ID__' = $TenantId
  '__CLIENT_ID__' = $aadApplication.AppId
  '__MAIL_RECIPIENT__' = $(if ($env:MAIL_RECIPIENT) { $env:MAIL_RECIPIENT } else { '' })
  '__FAIL_ON_TEST_FAILURES__' = $FailOnTestFailures.ToString().ToLower()
}

$renderedPipeline = $templateContent
foreach ($key in $replacementMap.Keys) {
  $renderedPipeline = $renderedPipeline.Replace($key, [string]$replacementMap[$key])
}

$pipelineFiles = @(
  [pscustomobject]@{
    Path = $pipelineRepoPath
    Content = $renderedPipeline
  },
  [pscustomobject]@{
    Path = 'scripts/Invoke-MaesterAzureDevOpsRun.ps1'
    Content = $runnerScriptContent
  }
)

$pushResult = [pscustomobject]@{
  Pushed     = $false
  Changed    = $false
  Branch     = $DefaultBranch
  Repository = $repositoryUrl
}

$manualFilesPath = $null
if ($PushPipelineFiles) {
  try {
    $pushResult = Push-RepositoryFiles -RepositoryUrl $repositoryUrl -Branch $DefaultBranch -BearerToken $devOpsToken -Files $pipelineFiles
    if ($pushResult.Pushed) {
      Write-Host "Pipeline files pushed to repository '$AdoRepositoryName' branch '$DefaultBranch'."
    }
    elseif (-not $pushResult.Changed) {
      Write-Host 'Pipeline files were already up to date. No push was required.'
    }
  }
  catch {
    Write-Warning "Automatic pipeline file push failed. Falling back to manual instructions. Error: $($_.Exception.Message)"

    $manualFilesPath = Join-Path -Path $projectRoot -ChildPath ("outputs/{0}-pipeline-files" -f $EnvironmentName)
    if (Test-Path -Path $manualFilesPath) {
      Remove-Item -Path $manualFilesPath -Recurse -Force
    }
    New-Item -Path $manualFilesPath -ItemType Directory -Force | Out-Null

    foreach ($file in $pipelineFiles) {
      $target = Join-Path -Path $manualFilesPath -ChildPath $file.Path
      $targetDir = Split-Path -Path $target -Parent
      if (-not (Test-Path -Path $targetDir)) {
        New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
      }
      Set-Content -Path $target -Value $file.Content -Encoding utf8
    }

    Write-Warning "Manual pipeline files created at: $manualFilesPath"
  }
}

if (-not $PushPipelineFiles) {
  Write-Host 'PushPipelineFiles=false, skipping automatic repository push.'
}

Set-AzdEnvValue -Name 'AZDO_PIPELINE_FILES_PUSHED' -Value $pushResult.Pushed.ToString().ToLower()
Set-AzdEnvValue -Name 'AZDO_FAIL_ON_TEST_FAILURES' -Value $FailOnTestFailures.ToString().ToLower()
if ($manualFilesPath) {
  Set-AzdEnvValue -Name 'AZDO_MANUAL_PIPELINE_FILES_PATH' -Value $manualFilesPath
}
else {
  Set-AzdEnvValue -Name 'AZDO_MANUAL_PIPELINE_FILES_PATH' -Value ''
}

$pipeline = $null
try {
  $pipeline = Get-ADOPSPipeline -Project $AdoProject -Name $AdoPipelineName -Organization $AdoOrganization -ErrorAction Stop
}
catch {
  $pipeline = $null
}

if (-not $pipeline) {
  Write-Host "Creating pipeline '$AdoPipelineName'..."
  try {
    $pipeline = New-ADOPSPipeline -Project $AdoProject -Name $AdoPipelineName -Repository $AdoRepositoryName -YamlPath "/$pipelineRepoPath" -Organization $AdoOrganization
  } catch {
    if ($manualFilesPath) {
      throw "Pipeline creation failed because the YAML file is not yet in repository '$AdoRepositoryName'. Upload files from '$manualFilesPath' and rerun Setup-PostDeploy.ps1. Error: $($_.Exception.Message)"
    }
    throw
  }
}

Set-AzdEnvValue -Name 'AZDO_PIPELINE_NAME' -Value $AdoPipelineName
Set-AzdEnvValue -Name 'AZDO_PIPELINE_ID' -Value ([string]$pipeline.id)

$pipelineUrl = "https://dev.azure.com/$AdoOrganization/$AdoProject/_build?definitionId=$($pipeline.id)"
Set-AzdEnvValue -Name 'AZDO_PIPELINE_URL' -Value $pipelineUrl

$validationResult = [pscustomobject]@{
  ValidationPassed = 'skipped'
  PipelineName     = $AdoPipelineName
  PipelineId       = $pipeline.id
  RunId            = 'n/a'
  FinalState       = 'skipped'
  FinalResult      = 'skipped'
  RunUrl           = $pipelineUrl
  CompletedAt      = (Get-Date).ToString('o')
}

if ($ValidatePipelineRun) {
  Write-Host 'Starting and validating initial Azure DevOps pipeline run...'
  $validationResult = & "$PSScriptRoot\Invoke-PipelineValidation.ps1" `
    -AdoOrganization $AdoOrganization `
    -AdoProject $AdoProject `
    -PipelineName $AdoPipelineName `
    -Branch $DefaultBranch `
    -TimeoutMinutes 45 `
    -SubscriptionId $SubscriptionId `
    -TenantId $TenantId `
    -PassThru

  Set-AzdEnvValue -Name 'AZDO_LAST_PIPELINE_RUN_ID' -Value ([string]$validationResult.RunId)
  if ($validationResult.RunUrl) {
    Set-AzdEnvValue -Name 'AZDO_LAST_PIPELINE_RUN_URL' -Value $validationResult.RunUrl
  }
}
$summaryDir = Join-Path -Path $projectRoot -ChildPath 'outputs'
if (-not (Test-Path -Path $summaryDir)) {
  New-Item -Path $summaryDir -ItemType Directory -Force | Out-Null
}

$summaryPath = Join-Path -Path $summaryDir -ChildPath ("{0}-setup-summary.md" -f $EnvironmentName)
$summaryLines = @()
$summaryLines += '# Deployment and Validation Summary'
$summaryLines += ''
$summaryLines += "Generated: $(Get-Date -Format u)"
$summaryLines += "Environment: $EnvironmentName"
$summaryLines += "Subscription: $SubscriptionId"
$summaryLines += "Resource group: $ResourceGroupName"
$summaryLines += "Azure DevOps organization: $AdoOrganization"
$summaryLines += "Azure DevOps project: $AdoProject"
$summaryLines += "Azure DevOps repository: $AdoRepositoryName"
$summaryLines += "Azure DevOps repository id: $repositoryId"
$summaryLines += "Azure DevOps pipeline: $AdoPipelineName"
$summaryLines += "Azure DevOps pipeline id: $($pipeline.id)"
$summaryLines += "Azure DevOps pipeline url: $pipelineUrl"
$summaryLines += "Azure DevOps service connection: $AdoServiceConnectionName"
$summaryLines += "Azure DevOps service connection id: $serviceConnectionId"
$summaryLines += "Workload identity app display name: $workloadIdentityDisplayName"
$summaryLines += "Workload identity appId: $($aadApplication.AppId)"
$summaryLines += "Workload identity app objectId: $($aadApplication.Id)"
$summaryLines += "Workload identity service principal objectId: $($servicePrincipal.Id)"
$summaryLines += "Repository auto-create enabled: $($CreateRepositoryIfMissing.ToString().ToLower())"
$summaryLines += "Pipeline auto-push enabled: $($PushPipelineFiles.ToString().ToLower())"
$summaryLines += "Pipeline validation enabled: $($ValidatePipelineRun.ToString().ToLower())"
$summaryLines += "Fail pipeline step on Maester failed tests: $($FailOnTestFailures.ToString().ToLower())"
$summaryLines += "Pipeline files push result: $($pushResult.Pushed.ToString().ToLower())"
$summaryLines += "Manual pipeline files path: $(if ($manualFilesPath) { $manualFilesPath } else { 'n/a' })"
$summaryLines += "Schedule cron: $ScheduleCron"
$summaryLines += "Default branch: $DefaultBranch"
$summaryLines += "Include web app: $($includeWebApp.ToString().ToLower())"
$summaryLines += "Include Exchange: $([bool]$IncludeExchange)"
$summaryLines += "Include Teams: $([bool]$IncludeTeams)"
$summaryLines += "Include Azure: $([bool]$IncludeAzure)"
$summaryLines += "Permission profile: $PermissionProfile"
$summaryLines += "Azure RBAC scopes: $(@($AzureScopes) -join ';')"
$summaryLines += "Exchange setup status: $exchangeSetupStatus"
$summaryLines += "Teams setup status: $teamsSetupStatus"
$summaryLines += "Azure setup status: $azureSetupStatus"
$summaryLines += "Security group object id: $(if ($SecurityGroupObjectId) { $SecurityGroupObjectId } else { 'n/a' })"
$summaryLines += "Security group display name: $(if ($SecurityGroupDisplayName) { $SecurityGroupDisplayName } else { 'n/a' })"
$summaryLines += ''
$summaryLines += '## Resources Created'
$summaryLines += "- Storage Account: $($storageResource.name)"
$summaryLines += "- Web App: $(if ($webAppResource) { $webAppResource.name } else { 'not deployed' })"
$summaryLines += ''
$summaryLines += '## Role Assignments Created'
$summaryLines += "- Base Azure role assignment ids: $(@($baseRoleAssignmentIds) -join ';')"
$summaryLines += "- Exchange app role assignment ids: $(@($exoAppRoleAssignmentIds) -join ';')"
$summaryLines += "- Teams role assignment ids: $(@($teamsRoleAssignmentIds) -join ';')"
$summaryLines += "- Azure role assignment ids: $(@($azureRoleAssignmentIds) -join ';')"
$summaryLines += ''
$summaryLines += '## Validation Results'
$summaryLines += "- Initial pipeline run status: $($validationResult.FinalResult)"
$summaryLines += "- Initial pipeline run id: $($validationResult.RunId)"
$summaryLines += "- Initial pipeline run url: $($validationResult.RunUrl)"
$summaryLines += "- Validation completed at: $($validationResult.CompletedAt)"

Set-Content -Path $summaryPath -Value ($summaryLines -join [Environment]::NewLine) -Encoding utf8
Write-Host "Deployment summary written to: $summaryPath"







