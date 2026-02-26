[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$AdoOrganization,

  [Parameter(Mandatory = $true)]
  [string]$AdoProject,

  [Parameter(Mandatory = $true)]
  [string]$PipelineName,

  [Parameter(Mandatory = $false)]
  [string]$Branch = 'main',

  [Parameter(Mandatory = $false)]
  [int]$TimeoutMinutes = 45,

  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$TenantId,

  [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Get-OptionalPropertyValue {
  param(
    [Parameter(Mandatory = $false)]
    $InputObject,

    [Parameter(Mandatory = $true)]
    [string]$PropertyName
  )

  if ($null -eq $InputObject) {
    return $null
  }

  $property = $InputObject.PSObject.Properties | Where-Object { $_.Name -ieq $PropertyName } | Select-Object -First 1
  if ($property) {
    return $property.Value
  }

  return $null
}

function Test-RunContainsExpectedMaesterFailures {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [string]$Project,

    [Parameter(Mandatory = $true)]
    [string]$RunId
  )

  try {
    $logsUri = "https://dev.azure.com/$Organization/$Project/_apis/build/builds/$RunId/logs?api-version=7.1-preview.2"
    $logsResponse = Invoke-ADOPSRestMethod -Method GET -Uri $logsUri
    $logItems = @($logsResponse.value)

    foreach ($logItem in $logItems) {
      $logUrl = [string](Get-OptionalPropertyValue -InputObject $logItem -PropertyName 'url')
      if ([string]::IsNullOrWhiteSpace($logUrl)) {
        continue
      }

      $logContent = Invoke-ADOPSRestMethod -Method GET -Uri $logUrl
      $logText = [string]$logContent
      if ($logText -match 'Maester test\(s\) failed' -or $logText -match 'There are one or more test failures detected in result files') {
        return $true
      }
    }
  }
  catch {
    Write-Verbose ("Could not inspect pipeline run logs for failure classification. Error: {0}" -f $_.Exception.Message)
  }

  return $false
}

Import-Module Az.Accounts -Force
Import-Module ADOPS -Force

if (-not $SubscriptionId) {
  $SubscriptionId = $env:AZURE_SUBSCRIPTION_ID
}
if (-not $TenantId -and $env:AZURE_TENANT_ID) {
  $TenantId = $env:AZURE_TENANT_ID
}

if ($SubscriptionId) {
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
}

$tokenResponse = Get-AzAccessToken -ResourceUrl '499b84ac-1321-427f-aa17-267ca6975798'
$devOpsToken = ConvertTo-PlainTextToken -TokenValue $tokenResponse.Token
Connect-ADOPS -Organization $AdoOrganization -OAuthToken $devOpsToken -SkipVerification | Out-Null

$pipeline = Get-ADOPSPipeline -Project $AdoProject -Name $PipelineName -Organization $AdoOrganization
if (-not $pipeline) {
  throw "Pipeline '$PipelineName' was not found in project '$AdoProject'."
}

$run = Start-ADOPSPipeline -Project $AdoProject -Name $PipelineName -Branch $Branch -Organization $AdoOrganization
$pipelineId = [string](Get-OptionalPropertyValue -InputObject $pipeline -PropertyName 'id')
$runId = [string](Get-OptionalPropertyValue -InputObject $run -PropertyName 'id')
if (-not $runId) {
  throw "Pipeline '$PipelineName' was started but run id could not be determined."
}

Write-Host "Started pipeline run id: $runId"

$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$runState = [string](Get-OptionalPropertyValue -InputObject $run -PropertyName 'state')
if ([string]::IsNullOrWhiteSpace($runState)) {
  $runState = 'unknown'
}
$runResult = [string](Get-OptionalPropertyValue -InputObject $run -PropertyName 'result')
if ([string]::IsNullOrWhiteSpace($runResult)) {
  $runResult = 'unknown'
}
$runUrl = $null

$runDetailsUri = "https://dev.azure.com/$AdoOrganization/$AdoProject/_apis/pipelines/$pipelineId/runs/$($runId)?api-version=7.1-preview.1"
while ((Get-Date) -lt $deadline) {
  $runDetails = Invoke-ADOPSRestMethod -Method GET -Uri $runDetailsUri
  $detailsState = [string](Get-OptionalPropertyValue -InputObject $runDetails -PropertyName 'state')
  if (-not [string]::IsNullOrWhiteSpace($detailsState)) {
    $runState = $detailsState
  }

  $detailsResult = [string](Get-OptionalPropertyValue -InputObject $runDetails -PropertyName 'result')
  if (-not [string]::IsNullOrWhiteSpace($detailsResult)) {
    $runResult = $detailsResult
  }

  $links = Get-OptionalPropertyValue -InputObject $runDetails -PropertyName '_links'
  $webLink = Get-OptionalPropertyValue -InputObject $links -PropertyName 'web'
  $href = [string](Get-OptionalPropertyValue -InputObject $webLink -PropertyName 'href')
  if (-not [string]::IsNullOrWhiteSpace($href)) {
    $runUrl = $href
  }

  Write-Host "Pipeline run status: state=$runState result=$runResult"

  if ($runState -eq 'completed') {
    break
  }

  Start-Sleep -Seconds 20
}

if ($runState -ne 'completed') {
  throw "Pipeline run '$runId' did not complete within $TimeoutMinutes minutes. Last state: $runState"
}

$validationPassed = $false
if ($runResult -eq 'succeeded') {
  $validationPassed = $true
}
elseif ($runResult -eq 'failed') {
  $isExpectedFailure = Test-RunContainsExpectedMaesterFailures -Organization $AdoOrganization -Project $AdoProject -RunId $runId
  if ($isExpectedFailure) {
    Write-Warning "Pipeline run '$runId' completed with result 'failed' because Maester reported test findings. Treating this as successful validation."
    $validationPassed = $true
  }
  else {
    if ($runUrl) {
      throw "Pipeline run '$runId' completed with result '$runResult'. Details: $runUrl"
    }
    throw "Pipeline run '$runId' completed with result '$runResult'."
  }
}
else {
  if ($runUrl) {
    throw "Pipeline run '$runId' completed with result '$runResult'. Details: $runUrl"
  }
  throw "Pipeline run '$runId' completed with result '$runResult'."
}

Write-Host "Pipeline validation completed successfully. Run id: $runId"
if ($runUrl) {
  Write-Host "Run URL: $runUrl"
}

$result = [pscustomobject]@{
  ValidationPassed = $validationPassed
  PipelineName     = $PipelineName
  PipelineId       = $pipelineId
  RunId            = $runId
  FinalState       = $runState
  FinalResult      = $runResult
  RunUrl           = $runUrl
  CompletedAt      = (Get-Date).ToString('o')
}

if ($PassThru) {
  return $result
}
