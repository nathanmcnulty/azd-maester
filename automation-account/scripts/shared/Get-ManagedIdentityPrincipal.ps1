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

Import-Module Az.Accounts -Force

$resourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/$ProviderNamespace/$ResourceType/$ResourceName"
$response = Invoke-AzRestMethod -Method GET -Path "${resourceId}?api-version=$ApiVersion"
if ($response.StatusCode -lt 200 -or $response.StatusCode -gt 299) {
  throw "Failed to read resource '$resourceId'. Status: $($response.StatusCode)"
}

$payload = $response.Content | ConvertFrom-Json
if (-not $payload.identity.principalId) {
  throw "Resource '$resourceId' does not expose a system-assigned identity principalId."
}

$payload.identity.principalId
