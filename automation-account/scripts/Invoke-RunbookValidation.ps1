[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$TenantId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$AutomationAccountName,

  [string]$RunbookName = 'maester-runbook',

  [int]$TimeoutMinutes = 20,

  [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module Az.Accounts -Force

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

try {
  Get-AzAccessToken -ResourceTypeName Arm | Out-Null
}
catch {
  $connectParameters = @{ Subscription = $SubscriptionId }
  if ($TenantId) {
    $connectParameters['Tenant'] = $TenantId
  }
  Connect-AzAccount @connectParameters | Out-Null
}

$apiVersion = '2023-11-01'
$jobId = [guid]::NewGuid().ToString()
$basePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName"

$jobBody = @{
  properties = @{
    runbook = @{
      name = $RunbookName
    }
    parameters = @{}
  }
} | ConvertTo-Json -Depth 10

Invoke-AzRestMethod -Method PUT -Path "$basePath/jobs/${jobId}?api-version=$apiVersion" -Payload $jobBody | Out-Null
Write-Host "Started runbook job: $jobId"

$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$status = 'New'
do {
  Start-Sleep -Seconds 15
  $jobResponse = Invoke-AzRestMethod -Method GET -Path "$basePath/jobs/${jobId}?api-version=$apiVersion"
  $job = $jobResponse.Content | ConvertFrom-Json
  $status = $job.properties.status
  Write-Host "Job status: $status"
} while ($status -in @('New', 'Activating', 'Running', 'Queued') -and (Get-Date) -lt $deadline)

$streams = @()
$streamsPath = "$basePath/jobs/${jobId}/streams?api-version=$apiVersion"
do {
  $streamsResponse = Invoke-AzRestMethod -Method GET -Path $streamsPath
  $streamsPayload = $streamsResponse.Content | ConvertFrom-Json
  $hasValueProperty = $false
  $hasNextLinkProperty = $false
  if ($streamsPayload -and $streamsPayload.PSObject) {
    $hasValueProperty = $streamsPayload.PSObject.Properties.Match('value').Count -gt 0
    $hasNextLinkProperty = $streamsPayload.PSObject.Properties.Match('nextLink').Count -gt 0
  }

  if ($streamsPayload -is [System.Array]) {
    $streams += $streamsPayload
    $nextLink = $null
  }
  elseif ($hasValueProperty -and $streamsPayload.value) {
    $streams += $streamsPayload.value
    $nextLink = if ($hasNextLinkProperty) { $streamsPayload.nextLink } else { $null }
  }
  else {
    $nextLink = $null
  }
  if ($nextLink) {
    $streamsPath = if ($nextLink -like 'https://*') {
      $nextLink -replace '^https://management\.azure\.com', ''
    }
    else {
      $nextLink
    }
  }
} while ($nextLink)

foreach ($stream in $streams) {
  $streamType = $stream.properties.streamType
  $streamId = if ($stream.properties.jobStreamId) { $stream.properties.jobStreamId } else { ($stream.id -split '/')[-1] }
  $streamContent = Invoke-AzRestMethod -Method GET -Path "$basePath/jobs/${jobId}/streams/${streamId}?api-version=$apiVersion"
  $detail = $streamContent.Content | ConvertFrom-Json
  Write-Host "[$streamType] $($detail.properties.summary)"
}

if ($status -ne 'Completed') {
  $jobResponse = Invoke-AzRestMethod -Method GET -Path "$basePath/jobs/${jobId}?api-version=$apiVersion"
  $job = $jobResponse.Content | ConvertFrom-Json
  $exception = $job.properties.exception
  if ($exception) {
    throw "Runbook job did not complete successfully. Final status: $status. Exception: $exception"
  }
  throw "Runbook job did not complete successfully. Final status: $status"
}

Write-Host 'Runbook validation completed successfully.'

$result = [pscustomobject]@{
  ValidationPassed      = $true
  JobId                 = $jobId
  FinalStatus           = $status
  SubscriptionId        = $SubscriptionId
  ResourceGroupName     = $ResourceGroupName
  AutomationAccountName = $AutomationAccountName
  RunbookName           = $RunbookName
  CompletedAt           = (Get-Date).ToString('o')
}

if ($PassThru) {
  return $result
}