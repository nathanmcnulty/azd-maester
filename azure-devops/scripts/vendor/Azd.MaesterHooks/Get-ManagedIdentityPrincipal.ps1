[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$ProviderNamespace,

  [Parameter(Mandatory = $true)]
  [string]$ResourceType,

  [Parameter(Mandatory = $true)]
  [string]$ResourceName,

  [string]$ApiVersion = '2023-01-01'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/$ProviderNamespace/$ResourceType/$ResourceName"
$armToken = az account get-access-token --subscription $SubscriptionId --resource https://management.azure.com/ --query accessToken -o tsv
$maxAttempts = 12
$retryDelaySeconds = 5
$principalId = $null
$lastError = $null

for ($attempt = 1; $attempt -le $maxAttempts -and [string]::IsNullOrWhiteSpace($principalId); $attempt++) {
  try {
    $payload = Invoke-RestMethod -Method GET -Uri "https://management.azure.com${resourceId}?api-version=$ApiVersion" -Headers @{ Authorization = "Bearer $armToken" }
    if (-not $payload) {
      throw "Failed to read resource '$resourceId'."
    }

    $identityProperty = $payload.PSObject.Properties['identity']
    $principalProperty = if ($identityProperty -and $identityProperty.Value) {
      $identityProperty.Value.PSObject.Properties['principalId']
    }

    if ($principalProperty -and -not [string]::IsNullOrWhiteSpace([string]$principalProperty.Value)) {
      $principalId = [string]$principalProperty.Value
      break
    }

    $lastError = "Resource '$resourceId' does not expose a system-assigned identity principalId yet."
  }
  catch {
    $lastError = $_.Exception.Message
  }

  if ($attempt -lt $maxAttempts) {
    Start-Sleep -Seconds $retryDelaySeconds
  }
}

if ([string]::IsNullOrWhiteSpace($principalId)) {
  throw "Unable to resolve the managed identity principalId for '$resourceId' after $maxAttempts attempts. Last error: $lastError"
}

$principalId
