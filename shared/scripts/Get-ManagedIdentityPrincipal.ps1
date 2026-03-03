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
$armToken = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
$payload = Invoke-RestMethod -Method GET -Uri "https://management.azure.com${resourceId}?api-version=$ApiVersion" -Headers @{ Authorization = "Bearer $armToken" }
if (-not $payload) {
  throw "Failed to read resource '$resourceId'."
}
if (-not $payload.identity.principalId) {
  throw "Resource '$resourceId' does not expose a system-assigned identity principalId."
}

$payload.identity.principalId
