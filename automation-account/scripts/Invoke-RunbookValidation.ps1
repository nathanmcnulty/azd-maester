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

if ($SubscriptionId) { az account set --subscription $SubscriptionId 2>$null | Out-Null }
$azAccount = az account show 2>$null | ConvertFrom-Json
if (-not $azAccount) { throw 'Not authenticated. Run: azd auth login' }
if (-not $SubscriptionId) { $SubscriptionId = $azAccount.id }
if (-not $TenantId) { $TenantId = $azAccount.tenantId }
$armToken = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
$armHeaders = @{ Authorization = "Bearer $armToken" }

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
} | ConvertTo-Json -Depth 10 -Compress

Invoke-RestMethod -Method PUT -Uri "https://management.azure.com$basePath/jobs/${jobId}?api-version=$apiVersion" -Headers $armHeaders -Body $jobBody -ContentType 'application/json' | Out-Null
Write-Host "Started runbook job: $jobId"

$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$status = 'New'
do {
  Start-Sleep -Seconds 15
  $job = Invoke-RestMethod -Method GET -Uri "https://management.azure.com$basePath/jobs/${jobId}?api-version=$apiVersion" -Headers $armHeaders
  $status = $job.properties.status
  Write-Host "Job status: $status"
} while ($status -in @('New', 'Activating', 'Running', 'Queued') -and (Get-Date) -lt $deadline)

$streams = @()
$streamsUrl = "https://management.azure.com$basePath/jobs/${jobId}/streams?api-version=$apiVersion"
do {
  $streamsPayload = Invoke-RestMethod -Method GET -Uri $streamsUrl -Headers $armHeaders
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
    $streamsUrl = if ($nextLink -like 'https://*') {
      $nextLink
    }
    else {
      "https://management.azure.com$nextLink"
    }
  }
} while ($nextLink)

foreach ($stream in $streams) {
  $streamType = $stream.properties.streamType
  $streamId = if ($stream.properties.jobStreamId) { $stream.properties.jobStreamId } else { ($stream.id -split '/')[-1] }
  $detail = Invoke-RestMethod -Method GET -Uri "https://management.azure.com$basePath/jobs/${jobId}/streams/${streamId}?api-version=$apiVersion" -Headers $armHeaders
  Write-Host "[$streamType] $($detail.properties.summary)"
}

if ($status -ne 'Completed') {
  $job = Invoke-RestMethod -Method GET -Uri "https://management.azure.com$basePath/jobs/${jobId}?api-version=$apiVersion" -Headers $armHeaders
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