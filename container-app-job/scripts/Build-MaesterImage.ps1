[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $false)]
  [string]$EnvironmentName,

  [Parameter(Mandatory = $false)]
  [string]$ImageTag = 'latest'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $SubscriptionId) {
  $SubscriptionId = $env:AZURE_SUBSCRIPTION_ID
}
if (-not $SubscriptionId) {
  throw 'SubscriptionId is required. Pass -SubscriptionId or set AZURE_SUBSCRIPTION_ID.'
}

if (-not $EnvironmentName) {
  $EnvironmentName = if ($env:AZURE_ENV_NAME) { $env:AZURE_ENV_NAME } else { 'dev' }
}

$resolvedResourceGroupName = if ($ResourceGroupName) { $ResourceGroupName } elseif ($env:AZURE_RESOURCE_GROUP) { $env:AZURE_RESOURCE_GROUP } else { "rg-$EnvironmentName" }
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

# Discover ACR in the resource group
$acrListJson = & az acr list --resource-group $resolvedResourceGroupName --query '[].{name:name,loginServer:loginServer}' -o json --subscription $SubscriptionId
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($acrListJson)) {
  throw "Failed to list Azure Container Registries in resource group '$resolvedResourceGroupName'."
}

$acrList = $acrListJson | ConvertFrom-Json
if (-not $acrList -or $acrList.Count -eq 0) {
  throw "No Azure Container Registry found in resource group '$resolvedResourceGroupName'. Ensure -IncludeACR was set during provisioning."
}

$acr = $acrList | Where-Object { $_.name -like 'crmaester*' } | Select-Object -First 1
if (-not $acr) {
  $acr = $acrList[0]
}

$acrName = $acr.name
$acrLoginServer = $acr.loginServer
$imageFqdn = "${acrLoginServer}/maester:${ImageTag}"

Write-Host "Building and pushing Maester image to ACR '$acrName'..."
Write-Host "Image: $imageFqdn"

# Build remotely using az acr build (no local Docker required)
& az acr build `
  --registry $acrName `
  --resource-group $resolvedResourceGroupName `
  --subscription $SubscriptionId `
  --image "maester:${ImageTag}" `
  --file "$projectRoot\Dockerfile" `
  $projectRoot
if ($LASTEXITCODE -ne 0) {
  throw "ACR build failed for image 'maester:${ImageTag}'."
}

Write-Host "Image built and pushed: $imageFqdn"

# Update the Container App Job to use the ACR image
$preferredJobName = "caj-maester-$($EnvironmentName.ToLower())"
Write-Host "Updating Container App Job '$preferredJobName' to use image '$imageFqdn'..."

Import-Module Az.Accounts -Force
$jobPath = "/subscriptions/$SubscriptionId/resourceGroups/$resolvedResourceGroupName/providers/Microsoft.App/jobs/${preferredJobName}?api-version=2024-03-01"
$jobResponse = Invoke-AzRestMethod -Method GET -Path $jobPath
if ($jobResponse.StatusCode -ne 200) {
  throw "Failed to read Container App Job '$preferredJobName'. HTTP $($jobResponse.StatusCode)"
}

$jobPayload = $jobResponse.Content | ConvertFrom-Json
$jobPayload.properties.template.containers[0].image = $imageFqdn

# Configure ACR registry on the job (not done during Bicep to avoid circular dependency)
$registryEntry = @{
  server   = $acrLoginServer
  identity = 'system'
}
$existingRegistries = @($jobPayload.properties.configuration.registries | Where-Object { $_ -and $_.server })
$alreadyConfigured = $existingRegistries | Where-Object { $_.server -eq $acrLoginServer }
if (-not $alreadyConfigured) {
  $existingRegistries += $registryEntry
  $jobPayload.properties.configuration.registries = @($existingRegistries)
  Write-Host "Added ACR registry '$acrLoginServer' to Container App Job configuration."
}

# Remove read-only properties before PUT
$updateBody = @{
  location   = $jobPayload.location
  tags       = $jobPayload.tags
  identity   = $jobPayload.identity
  properties = $jobPayload.properties
} | ConvertTo-Json -Depth 30

$updateResponse = Invoke-AzRestMethod -Method PUT -Path $jobPath -Payload $updateBody
if ($updateResponse.StatusCode -lt 200 -or $updateResponse.StatusCode -gt 299) {
  throw "Failed to update Container App Job image. HTTP $($updateResponse.StatusCode): $($updateResponse.Content)"
}

Write-Host "Container App Job '$preferredJobName' updated to image '$imageFqdn'."
