[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$TenantId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$ContainerAppJobName,

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

$apiVersion = '2024-03-01'
$basePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.App/jobs/$ContainerAppJobName"

# Start the Container App Job execution
$startResponse = Invoke-AzRestMethod -Method POST -Path "$basePath/start?api-version=$apiVersion" -Payload '{}'
if ($startResponse.StatusCode -lt 200 -or $startResponse.StatusCode -gt 299) {
  throw "Failed to start Container App Job '$ContainerAppJobName'. HTTP $($startResponse.StatusCode): $($startResponse.Content)"
}

$startPayload = $startResponse.Content | ConvertFrom-Json
$executionName = $startPayload.name
if ([string]::IsNullOrWhiteSpace($executionName)) {
  # Some API versions return the execution name in different fields
  $executionName = $startPayload.id -split '/' | Select-Object -Last 1
}

Write-Host "Started Container App Job execution: $executionName"

# Poll execution status
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$status = 'Running'
do {
  Start-Sleep -Seconds 15
  $execResponse = Invoke-AzRestMethod -Method GET -Path "$basePath/executions/${executionName}?api-version=$apiVersion"
  if ($execResponse.StatusCode -ne 200) {
    Write-Warning "Failed to check execution status. HTTP $($execResponse.StatusCode). Retrying..."
    continue
  }

  $execPayload = $execResponse.Content | ConvertFrom-Json
  $status = $execPayload.properties.status
  Write-Host "Execution status: $status"
} while ($status -in @('Running', 'Processing', 'Unknown') -and (Get-Date) -lt $deadline)

# Attempt to retrieve container logs via the console log stream
try {
  $logStreamPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.App/jobs/$ContainerAppJobName/executions/${executionName}?api-version=$apiVersion"
  $logResponse = Invoke-AzRestMethod -Method GET -Path $logStreamPath
  if ($logResponse.StatusCode -eq 200) {
    $logPayload = $logResponse.Content | ConvertFrom-Json
    if ($logPayload.properties.template -and $logPayload.properties.template.containers) {
      $containerStatus = $logPayload.properties.template.containers[0]
      if ($containerStatus) {
        Write-Host "Container details retrieved for execution '$executionName'."
      }
    }
  }
}
catch {
  Write-Warning "Could not retrieve container logs. Error: $($_.Exception.Message)"
}

if ($status -ne 'Succeeded') {
  # Try to get more details about the failure
  $detailResponse = Invoke-AzRestMethod -Method GET -Path "$basePath/executions/${executionName}?api-version=$apiVersion"
  if ($detailResponse.StatusCode -eq 200) {
    $detailPayload = $detailResponse.Content | ConvertFrom-Json
    $failureMessage = $null
    if ($detailPayload.properties -and $detailPayload.properties.PSObject.Properties.Match('status').Count -gt 0) {
      $failureMessage = "Final status: $($detailPayload.properties.status)"
    }
    if ($failureMessage) {
      throw "Container App Job execution did not succeed. $failureMessage"
    }
  }
  throw "Container App Job execution did not succeed. Final status: $status"
}

Write-Host 'Container App Job validation completed successfully.'

$result = [pscustomobject]@{
  ValidationPassed    = $true
  ExecutionName       = $executionName
  FinalStatus         = $status
  SubscriptionId      = $SubscriptionId
  ResourceGroupName   = $ResourceGroupName
  ContainerAppJobName = $ContainerAppJobName
  CompletedAt         = (Get-Date).ToString('o')
}

if ($PassThru) {
  return $result
}
