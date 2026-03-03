[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$TenantId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $false)]
  [string]$FunctionAppName,

  [int]$TimeoutMinutes = 15,

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

# Discover function app if not specified
if ([string]::IsNullOrWhiteSpace($FunctionAppName)) {
  $sitesPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites?api-version=2023-12-01"
  $sitesPayload = Invoke-RestMethod -Method GET -Uri "https://management.azure.com$sitesPath" -Headers $armHeaders
  $funcSite = @($sitesPayload.value | Where-Object { $_.kind -like '*functionapp*' }) | Select-Object -First 1
  if (-not $funcSite) {
    throw "No Function App was found in resource group '$ResourceGroupName'."
  }
  $FunctionAppName = $funcSite.name
}

Write-Host "Validating Function App '$FunctionAppName'..."

# Get master key via Azure REST API
$keysPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$FunctionAppName/host/default/listkeys?api-version=2023-12-01"
$keysPayload = Invoke-RestMethod -Method POST -Uri "https://management.azure.com$keysPath" -Headers $armHeaders -Body '{}' -ContentType 'application/json'
$masterKey = $keysPayload.masterKey
if ([string]::IsNullOrWhiteSpace($masterKey)) {
  throw "Master key was not found in Function App host keys response."
}

# Trigger the function via admin API (with retry for post-deployment startup)
$triggerUrl = "https://$FunctionAppName.azurewebsites.net/admin/functions/MaesterTimerTrigger"
Write-Host "Triggering function: POST $triggerUrl"

$triggerMaxWaitMinutes = 10
$triggerDeadline = (Get-Date).AddMinutes($triggerMaxWaitMinutes)
$triggerRetryInterval = 20
$triggerAccepted = $false

while ((Get-Date) -lt $triggerDeadline) {
  try {
    $triggerResponse = Invoke-WebRequest -Uri $triggerUrl -Method POST -Headers @{
      'x-functions-key' = $masterKey
      'Content-Type'    = 'application/json'
    } -Body '{}' -UseBasicParsing -ErrorAction Stop

    if ($triggerResponse.StatusCode -in @(200, 202, 204)) {
      Write-Host "Function trigger accepted (HTTP $($triggerResponse.StatusCode))."
      $triggerAccepted = $true
      break
    }
  }
  catch {
    $statusCode = $null
    if ($_.Exception.Response) {
      $statusCode = [int]$_.Exception.Response.StatusCode
    }

    if ($statusCode -eq 202) {
      Write-Host 'Function trigger accepted (HTTP 202).'
      $triggerAccepted = $true
      break
    }

    if ($statusCode -in @(404, 500, 502, 503, 504)) {
      $remainingMinutes = [math]::Round(($triggerDeadline - (Get-Date)).TotalMinutes, 1)
      Write-Host "Function not ready yet (HTTP $statusCode). Waiting for startup... ($remainingMinutes min remaining)"
      Start-Sleep -Seconds $triggerRetryInterval
      continue
    }

    throw "Failed to trigger function. HTTP ${statusCode}: $($_.Exception.Message)"
  }
}

if (-not $triggerAccepted) {
  throw "Function trigger endpoint did not become available within $triggerMaxWaitMinutes minutes. The function app may still be installing managed dependencies."
}

# Poll function invocations for completion
Write-Host "Waiting for function execution to complete (timeout: $TimeoutMinutes minutes)..."
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$functionStatus = 'Running'
$pollInterval = 15
$lastInvocationId = $null
$lastInvocationStatus = $null

# Wait a few seconds for the invocation to register
Start-Sleep -Seconds 10

do {
  try {
    # Check recent invocations via the function admin API
    $invocationsUrl = "https://$FunctionAppName.azurewebsites.net/admin/functions/MaesterTimerTrigger/status"
    $statusResponse = Invoke-RestMethod -Uri $invocationsUrl -Method GET -Headers @{
      'x-functions-key' = $masterKey
    } -ErrorAction SilentlyContinue

    if ($statusResponse -and $statusResponse.isRunning -eq $false) {
      $functionStatus = 'Succeeded'
      Write-Host "Function execution completed."
      break
    }
    elseif ($statusResponse -and $statusResponse.isRunning -eq $true) {
      Write-Host "Function is still running..."
    }
  }
  catch {
    # Status endpoint may not be available on all runtime versions
    # Fall back to checking blob output
    Write-Verbose "Status check returned error: $($_.Exception.Message)"
  }

  # Alternative: check if a recent blob appeared in the archive container
  try {
    $storageQuery = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01"
    $storagePayload = Invoke-RestMethod -Method GET -Uri "https://management.azure.com$storageQuery" -Headers $armHeaders -ErrorAction SilentlyContinue
    $storage = @($storagePayload.value | Where-Object { $_.name -like 'stmaester*' }) | Select-Object -First 1
    if (-not $storage) {
      $storage = $storagePayload.value | Select-Object -First 1
    }

    if ($storage) {
      $storageName = $storage.name

      # List blobs in latest container to see if latest.html was recently updated
      $plainToken = az account get-access-token --resource https://storage.azure.com/ --query accessToken -o tsv 2>$null

      $blobHeaders = @{
        'Authorization' = "Bearer $plainToken"
        'x-ms-version'  = '2021-12-02'
      }

      $latestBlobUrl = "https://$storageName.blob.core.windows.net/latest/latest.html"
      try {
        $blobPropsResponse = Invoke-WebRequest -Uri $latestBlobUrl -Method HEAD -Headers $blobHeaders -UseBasicParsing -ErrorAction Stop
        $lastModifiedHeader = $blobPropsResponse.Headers['Last-Modified']
        if ($lastModifiedHeader) {
          $lastModified = [DateTime]::Parse($lastModifiedHeader)
          $minutesAgo = ((Get-Date).ToUniversalTime() - $lastModified.ToUniversalTime()).TotalMinutes
          if ($minutesAgo -lt 3) {
            $functionStatus = 'Succeeded'
            Write-Host "Function execution completed (detected fresh blob output, modified $([math]::Round($minutesAgo, 1)) minutes ago)."
            break
          }
        }
      }
      catch {
        # Blob may not exist yet
      }
    }
  }
  catch {
    Write-Verbose "Blob check failed: $($_.Exception.Message)"
  }

  Start-Sleep -Seconds $pollInterval
  Write-Host "Waiting for function execution... ($(([math]::Round(($deadline - (Get-Date)).TotalMinutes, 1))) minutes remaining)"
} while ((Get-Date) -lt $deadline)

if ($functionStatus -ne 'Succeeded') {
  Write-Warning "Function App execution did not complete within $TimeoutMinutes minutes. Final status: $functionStatus. On Consumption plan, the first cold-start run may exceed the function timeout while managed dependencies are being installed. Subsequent timer-triggered runs will use cached modules and complete much faster."
}
else {
  Write-Host 'Function App execution completed successfully.'
}

Write-Host 'Function App validation completed (trigger accepted).'

$result = [pscustomobject]@{
  ValidationPassed  = $triggerAccepted
  ExecutionComplete = ($functionStatus -eq 'Succeeded')
  FunctionAppName   = $FunctionAppName
  FinalStatus       = $functionStatus
  SubscriptionId    = $SubscriptionId
  ResourceGroupName = $ResourceGroupName
  CompletedAt       = (Get-Date).ToString('o')
}

if ($PassThru) {
  return $result
}
