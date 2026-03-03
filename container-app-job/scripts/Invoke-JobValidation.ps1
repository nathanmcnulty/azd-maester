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

if ($SubscriptionId) { az account set --subscription $SubscriptionId 2>$null | Out-Null }
$azAccount = az account show 2>$null | ConvertFrom-Json
if (-not $azAccount) { throw 'Not authenticated. Run: azd auth login' }
if (-not $SubscriptionId) { $SubscriptionId = $azAccount.id }
if (-not $TenantId) { $TenantId = $azAccount.tenantId }
$armToken = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
$armHeaders = @{ Authorization = "Bearer $armToken" }

$apiVersion = '2024-03-01'
$basePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.App/jobs/$ContainerAppJobName"

# Start the Container App Job execution
$startPayload = Invoke-RestMethod -Method POST -Uri "https://management.azure.com$basePath/start?api-version=$apiVersion" -Headers $armHeaders -Body '{}' -ContentType 'application/json'
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
  $execPayload = Invoke-RestMethod -Method GET -Uri "https://management.azure.com$basePath/executions/${executionName}?api-version=$apiVersion" -Headers $armHeaders -ErrorAction SilentlyContinue
  if (-not $execPayload) {
    Write-Warning "Failed to check execution status. Retrying..."
    continue
  }

  $status = $execPayload.properties.status
  Write-Host "Execution status: $status"
} while ($status -in @('Running', 'Processing', 'Unknown') -and (Get-Date) -lt $deadline)

# Attempt to retrieve container logs via the console log stream
try {
  $logStreamPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.App/jobs/$ContainerAppJobName/executions/${executionName}?api-version=$apiVersion"
  $logPayload = Invoke-RestMethod -Method GET -Uri "https://management.azure.com$logStreamPath" -Headers $armHeaders -ErrorAction SilentlyContinue
  if ($logPayload -and $logPayload.properties.template -and $logPayload.properties.template.containers) {
    $containerStatus = $logPayload.properties.template.containers[0]
    if ($containerStatus) {
      Write-Host "Container details retrieved for execution '$executionName'."
    }
  }
}
catch {
  Write-Warning "Could not retrieve container logs. Error: $($_.Exception.Message)"
}

if ($status -ne 'Succeeded') {
  # Try to get more details about the failure
  $detailPayload = Invoke-RestMethod -Method GET -Uri "https://management.azure.com$basePath/executions/${executionName}?api-version=$apiVersion" -Headers $armHeaders -ErrorAction SilentlyContinue
  if ($detailPayload -and $detailPayload.properties -and $detailPayload.properties.PSObject.Properties.Match('status').Count -gt 0) {
    throw "Container App Job execution did not succeed. Final status: $($detailPayload.properties.status)"
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
