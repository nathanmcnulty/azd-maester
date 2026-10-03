[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$SubscriptionId,
  [string]$TenantId,
  [Parameter(Mandatory)][string]$ResourceGroupName,
  [string]$FunctionAppName,
  [string]$StorageAccountName,
  [ValidateRange(1, 120)][int]$TimeoutMinutes = 15,
  [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'vendor/Azd.MaesterHooks/Maester-SetupHelpers.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'FunctionValidation.Core.psm1') -Force

if (-not $FunctionAppName) { $FunctionAppName = $env:FUNCTION_APP_NAME }
if (-not $StorageAccountName) { $StorageAccountName = $env:STORAGE_ACCOUNT_NAME }
if ($FunctionAppName -notmatch '^[a-zA-Z0-9-]+$' -or $StorageAccountName -notmatch '^[a-z0-9]+$') {
  throw 'Validation requires exact FunctionAppName and StorageAccountName from the deployed environment.'
}

$account = Get-AzCliSubscriptionContext -SubscriptionId $SubscriptionId -TenantId $TenantId
if (-not $TenantId) { $TenantId = $account.tenantId }
$armToken = & az account get-access-token --subscription $SubscriptionId --resource https://management.azure.com/ --query accessToken -o tsv
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($armToken)) { throw 'Could not acquire ARM token for validation.' }
$armHeaders = @{ Authorization = "Bearer $armToken" }

# Exact target GETs prevent a stale environment setting from silently choosing a
# different resource in a group with multiple apps or storage accounts.
$sitePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/${FunctionAppName}?api-version=2023-12-01"
$site = Invoke-RestMethod -Method GET -Uri "https://management.azure.com$sitePath" -Headers $armHeaders -ErrorAction Stop
if ($site.name -ne $FunctionAppName -or $site.kind -notlike '*functionapp*') {
  throw "The selected resource '$FunctionAppName' is not the expected Function App."
}
$storagePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName" + '?api-version=2023-05-01'
$storage = Invoke-RestMethod -Method GET -Uri "https://management.azure.com$storagePath" -Headers $armHeaders -ErrorAction Stop
if ($storage.name -ne $StorageAccountName) { throw "The selected storage account '$StorageAccountName' was not found." }

$keysPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$FunctionAppName/host/default/listkeys?api-version=2023-12-01"
$keys = Invoke-RestMethod -Method POST -Uri "https://management.azure.com$keysPath" -Headers $armHeaders -Body '{}' -ContentType 'application/json' -ErrorAction Stop
$masterKey = $keys.masterKey
if ([string]::IsNullOrWhiteSpace($masterKey)) { throw 'Function App master key was not returned.' }

$storageToken = & az account get-access-token --subscription $SubscriptionId --resource https://storage.azure.com/ --query accessToken -o tsv
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($storageToken)) { throw 'Could not acquire storage token for validation.' }
$blobHeaders = @{ Authorization = "Bearer $storageToken"; 'x-ms-version' = '2021-12-02' }

function Get-HttpStatusCode {
  param($ErrorRecord)
  $exception = $ErrorRecord.Exception
  while ($exception) {
    if ($exception.PSObject.Properties['Response'] -and $exception.Response -and
        $exception.Response.PSObject.Properties['StatusCode']) {
      return [int]$exception.Response.StatusCode
    }
    $exception = $exception.InnerException
  }
  return $null
}

$validationId = [guid]::NewGuid()
$receiptUrl = "https://$StorageAccountName.blob.core.windows.net/validation/$($validationId.ToString('D')).json"
try {
  Invoke-WebRequest -Method HEAD -Uri $receiptUrl -Headers $blobHeaders -UseBasicParsing -ErrorAction Stop | Out-Null
  throw 'The newly generated validation receipt already exists; refusing to reuse it.'
}
catch {
  if ((Get-HttpStatusCode $_) -ne 404) { throw }
}

$triggerUrl = "https://$FunctionAppName.azurewebsites.net/admin/functions/MaesterValidationTrigger"
$body = @{ input = $validationId.ToString('D') } | ConvertTo-Json -Compress
$triggerDeadline = (Get-Date).AddMinutes(10)
$accepted = $false
while ((Get-Date) -lt $triggerDeadline) {
  try {
    $response = Invoke-WebRequest -Uri $triggerUrl -Method POST -Headers @{
      'x-functions-key' = $masterKey
      'Content-Type' = 'application/json'
    } -Body $body -UseBasicParsing -ErrorAction Stop
    if ([int]$response.StatusCode -ne 202) { throw "Validation trigger returned unexpected HTTP $($response.StatusCode)." }
    $accepted = $true
    break
  }
  catch {
    $code = Get-HttpStatusCode $_
    if ($code -notin @(404, 500, 502, 503, 504)) { throw }
    Start-Sleep -Seconds 20
  }
}
if (-not $accepted) { throw 'Validation trigger did not become available within ten minutes.' }

$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
while ((Get-Date) -lt $deadline) {
  try {
    $receipt = Invoke-RestMethod -Method GET -Uri $receiptUrl -Headers $blobHeaders -ErrorAction Stop
    Assert-MaesterValidationReceipt -Receipt $receipt -ValidationId $validationId | Out-Null
    $result = [pscustomobject]@{
      ValidationPassed = $true
      ExecutionComplete = $true
      FunctionAppName = $FunctionAppName
      FinalStatus = 'Succeeded'
      ValidationId = $validationId.ToString('D')
      InvocationId = $receipt.invocationId
      SubscriptionId = $SubscriptionId
      ResourceGroupName = $ResourceGroupName
      CompletedAt = (Get-Date).ToUniversalTime().ToString('o')
    }
    Write-Host "Function validation completed for request '$validationId'."
    if ($PassThru) { return $result }
    return
  }
  catch {
    if ((Get-HttpStatusCode $_) -ne 404) { throw }
  }
  Start-Sleep -Seconds 15
}
throw "Function validation request '$validationId' has no completed receipt after $TimeoutMinutes minutes."
