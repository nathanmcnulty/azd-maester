[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$EnvironmentName,

  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$Location = 'eastus2',

  [Parameter(Mandatory = $false)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $false)]
  [Alias('WebApp')]
  [switch]$IncludeWebApp,

  [Parameter(Mandatory = $false)]
  [switch]$IncludeExchange,

  [Parameter(Mandatory = $false)]
  [switch]$IncludeTeams,

  [Parameter(Mandatory = $false)]
  [switch]$IncludeAzure,

  [Parameter(Mandatory = $false)]
  [string[]]$AzureScopes,

  [Parameter(Mandatory = $false)]
  [string]$WebAppSku = 'F1',

  [Parameter(Mandatory = $false)]
  [ValidateSet('Minimal', 'Extended')]
  [string]$PermissionProfile,

  [Parameter(Mandatory = $false)]
  [string]$SecurityGroupObjectId,

  [Parameter(Mandatory = $false)]
  [string]$SecurityGroupDisplayName,

  [Parameter(Mandatory = $false)]
  [string]$TenantId,

  [Parameter(Mandatory = $false)]
  [string]$MailRecipient = '',

  [Parameter(Mandatory = $true)]
  [string]$AdoOrganization,

  [Parameter(Mandatory = $true)]
  [string]$AdoProject,

  [Parameter(Mandatory = $true)]
  [string]$AdoRepositoryName,

  [Parameter(Mandatory = $false)]
  [string]$AdoPipelineName = 'maester-weekly',

  [Parameter(Mandatory = $true)]
  [string]$AdoServiceConnectionName,

  [Parameter(Mandatory = $false)]
  [string]$PipelineYamlPath = '/azure-pipelines.yml',

  [Parameter(Mandatory = $false)]
  [string]$DefaultBranch = 'main',

  [Parameter(Mandatory = $false)]
  [string]$ScheduleCron = '0 0 * * 0',

  [Parameter(Mandatory = $false)]
  [bool]$CreateRepositoryIfMissing = $true,

  [Parameter(Mandatory = $false)]
  [bool]$PushPipelineFiles = $true,

  [Parameter(Mandatory = $false)]
  [bool]$ValidatePipelineRun = $true,

  [Parameter(Mandatory = $false)]
  [bool]$FailOnTestFailures = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot
Import-Module "$PSScriptRoot\shared\Maester-Helpers.psm1" -Force

if (-not $PSBoundParameters.ContainsKey('IncludeWebApp')) {
  $IncludeWebApp = $false
}

if (-not $PSBoundParameters.ContainsKey('IncludeExchange')) {
  $IncludeExchange = $false
}

if (-not $PSBoundParameters.ContainsKey('IncludeTeams')) {
  $IncludeTeams = $false
}

if (-not $PSBoundParameters.ContainsKey('IncludeAzure')) {
  $IncludeAzure = $false
}

if (-not $PSBoundParameters.ContainsKey('PermissionProfile') -or [string]::IsNullOrWhiteSpace($PermissionProfile)) {
  $PermissionProfile = 'Extended'
}

if ($IncludeWebApp -and [string]::IsNullOrWhiteSpace($SecurityGroupObjectId)) {
  throw 'SecurityGroupObjectId is required when IncludeWebApp is true.'
}

$normalizedLocation = ($Location -replace '\s+', '').ToLower()
$resourceGroupName = if (-not [string]::IsNullOrWhiteSpace($ResourceGroupName)) {
  $ResourceGroupName
}
else {
  "rg-$($EnvironmentName.ToLower())-$normalizedLocation"
}

$envNewOutput = & azd env new $EnvironmentName --subscription $SubscriptionId --location $Location --no-prompt 2>&1
if ($LASTEXITCODE -ne 0) {
  $alreadyExists = $envNewOutput | Where-Object { $_ -match 'already exists' }
  if ($alreadyExists) {
    Write-Host "Environment '$EnvironmentName' already exists. Selecting it."
  }
  else {
    $envNewOutput | ForEach-Object { Write-Host $_ }
    throw "azd env new failed for environment '$EnvironmentName'."
  }
}

Invoke-Azd -Arguments @('env', 'select', $EnvironmentName) -Operation 'env select target environment'

Invoke-Azd -Arguments @('env', 'set', 'AZURE_RESOURCE_GROUP', $resourceGroupName) -Operation 'set resource group'
Invoke-Azd -Arguments @('env', 'set', 'INCLUDE_WEB_APP', $IncludeWebApp.ToString().ToLower()) -Operation 'set include web app'
Invoke-Azd -Arguments @('env', 'set', 'INCLUDE_EXCHANGE', $IncludeExchange.ToString().ToLower()) -Operation 'set include exchange'
Invoke-Azd -Arguments @('env', 'set', 'INCLUDE_TEAMS', $IncludeTeams.ToString().ToLower()) -Operation 'set include teams'
Invoke-Azd -Arguments @('env', 'set', 'INCLUDE_AZURE', $IncludeAzure.ToString().ToLower()) -Operation 'set include azure'
Invoke-Azd -Arguments @('env', 'set', 'WEB_APP_SKU', $WebAppSku) -Operation 'set web app sku'
Invoke-Azd -Arguments @('env', 'set', 'PERMISSION_PROFILE', $PermissionProfile) -Operation 'set permission profile'
Invoke-Azd -Arguments @('env', 'set', 'VALIDATE_PIPELINE_ON_PROVISION', $ValidatePipelineRun.ToString().ToLower()) -Operation 'set pipeline validation on provision'
Invoke-Azd -Arguments @('env', 'set', 'MAIL_RECIPIENT', $MailRecipient) -Operation 'set mail recipient'

$effectiveAzureScopes = @()
if ($IncludeAzure -and $AzureScopes -and $AzureScopes.Count -gt 0) {
  $effectiveAzureScopes = @($AzureScopes)
}

$azureScopesSerialized = (@($effectiveAzureScopes) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) -join ';'
Invoke-Azd -Arguments @('env', 'set', 'AZURE_RBAC_SCOPES', $azureScopesSerialized) -Operation 'set azure rbac scopes'

if ($IncludeWebApp) {
  Invoke-Azd -Arguments @('env', 'set', 'SECURITY_GROUP_OBJECT_ID', $SecurityGroupObjectId) -Operation 'set security group'
  if (-not [string]::IsNullOrWhiteSpace($SecurityGroupDisplayName)) {
    Invoke-Azd -Arguments @('env', 'set', 'SECURITY_GROUP_DISPLAY_NAME', $SecurityGroupDisplayName) -Operation 'set security group display name'
  }
}

Invoke-Azd -Arguments @('env', 'set', 'AZDO_ORGANIZATION', $AdoOrganization) -Operation 'set Azure DevOps organization'
Invoke-Azd -Arguments @('env', 'set', 'AZDO_PROJECT', $AdoProject) -Operation 'set Azure DevOps project'
Invoke-Azd -Arguments @('env', 'set', 'AZDO_REPOSITORY', $AdoRepositoryName) -Operation 'set Azure DevOps repository'
Invoke-Azd -Arguments @('env', 'set', 'AZDO_PIPELINE_NAME', $AdoPipelineName) -Operation 'set Azure DevOps pipeline name'
Invoke-Azd -Arguments @('env', 'set', 'AZDO_SERVICE_CONNECTION_NAME', $AdoServiceConnectionName) -Operation 'set Azure DevOps service connection name'
Invoke-Azd -Arguments @('env', 'set', 'AZDO_PIPELINE_YAML_PATH', $PipelineYamlPath) -Operation 'set Azure DevOps pipeline yaml path'
Invoke-Azd -Arguments @('env', 'set', 'AZDO_DEFAULT_BRANCH', $DefaultBranch) -Operation 'set Azure DevOps default branch'
Invoke-Azd -Arguments @('env', 'set', 'AZDO_SCHEDULE_CRON', $ScheduleCron) -Operation 'set Azure DevOps schedule cron'
Invoke-Azd -Arguments @('env', 'set', 'AZDO_CREATE_REPO_IF_MISSING', $CreateRepositoryIfMissing.ToString().ToLower()) -Operation 'set Azure DevOps create repo flag'
Invoke-Azd -Arguments @('env', 'set', 'AZDO_PUSH_PIPELINE_FILES', $PushPipelineFiles.ToString().ToLower()) -Operation 'set Azure DevOps push pipeline files flag'
Invoke-Azd -Arguments @('env', 'set', 'AZDO_VALIDATE_PIPELINE_RUN', $ValidatePipelineRun.ToString().ToLower()) -Operation 'set Azure DevOps validate pipeline flag'
Invoke-Azd -Arguments @('env', 'set', 'AZDO_FAIL_ON_TEST_FAILURES', $FailOnTestFailures.ToString().ToLower()) -Operation 'set Azure DevOps fail on test failures flag'

if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
  Invoke-Azd -Arguments @('env', 'set', 'AZURE_TENANT_ID', $TenantId) -Operation 'set tenant id'
}

Write-Host "Environment '$EnvironmentName' is ready."
Write-Host "Resource group: $resourceGroupName"
Write-Host "Azure DevOps organization: $AdoOrganization"
Write-Host "Azure DevOps project: $AdoProject"
Write-Host "Azure DevOps repository: $AdoRepositoryName"
Write-Host "Azure DevOps pipeline: $AdoPipelineName"
Write-Host "Azure DevOps service connection: $AdoServiceConnectionName"
Write-Host "Schedule cron: $ScheduleCron"
Write-Host ("Web app enabled: {0}" -f $IncludeWebApp.ToString().ToLower())
Write-Host ("Include Exchange: {0}" -f $IncludeExchange.ToString().ToLower())
Write-Host ("Include Teams: {0}" -f $IncludeTeams.ToString().ToLower())
Write-Host ("Include Azure: {0}" -f $IncludeAzure.ToString().ToLower())
Write-Host "Azure RBAC scopes: $azureScopesSerialized"
Write-Host "Permission profile: $PermissionProfile"
Write-Host "Mail recipient: $(if ([string]::IsNullOrWhiteSpace($MailRecipient)) { '(none)' } else { $MailRecipient })"
Write-Host "Create repository if missing: $($CreateRepositoryIfMissing.ToString().ToLower())"
Write-Host "Push pipeline files: $($PushPipelineFiles.ToString().ToLower())"
Write-Host "Validate initial pipeline run: $($ValidatePipelineRun.ToString().ToLower())"
Write-Host "Fail pipeline step on Maester failed tests: $($FailOnTestFailures.ToString().ToLower())"
Write-Host 'Next command: azd provision --no-prompt --no-state'
