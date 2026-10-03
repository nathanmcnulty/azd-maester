[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $false)]
  [string]$EnvironmentName,

  [Parameter(Mandatory = $false)]
  [string]$ContainerAppJobName,

  [Parameter(Mandatory = $false)]
  [string]$AcrName,

  [Parameter(Mandatory = $false)]
  [string]$ImageTag = ([guid]::NewGuid().ToString('N'))
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
$acrListJson = & az acr list --resource-group $resolvedResourceGroupName --query '[].{name:name,loginServer:loginServer,tags:tags}' -o json --subscription $SubscriptionId
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($acrListJson)) {
  throw "Failed to list Azure Container Registries in resource group '$resolvedResourceGroupName'."
}

$acrList = @($acrListJson | ConvertFrom-Json)
if ($acrList.Count -eq 0) {
  throw "No Azure Container Registry found in resource group '$resolvedResourceGroupName'. Ensure -IncludeACR was set during provisioning."
}

$matchingAcr = @()
if ([string]::IsNullOrWhiteSpace($AcrName)) {
  $matchingAcr = @($acrList | Where-Object {
      $tags = if ($_.PSObject.Properties['tags']) { $_.tags } else { $null }
      $tags -and $tags.PSObject.Properties['environment'] -and
      $tags.PSObject.Properties['managedBy'] -and
      $tags.PSObject.Properties['workload'] -and
      $tags.PSObject.Properties['solution'] -and
      $tags.environment -eq $EnvironmentName.ToLowerInvariant() -and
      $tags.managedBy -eq 'azd' -and $tags.workload -eq 'maester' -and
      $tags.solution -eq 'container-app-job'
    })
}
else {
  $matchingAcr = @($acrList | Where-Object { $_.name -eq $AcrName })
}
if ($matchingAcr.Count -ne 1) {
  throw "Could not identify one Maester Azure Container Registry in resource group '$resolvedResourceGroupName'. Pass -AcrName from the deployment output."
}
$acr = $matchingAcr[0]

$acrName = $acr.name
$acrLoginServer = $acr.loginServer
$imageFqdn = "${acrLoginServer}/maester:${ImageTag}"

# Resolve the deployed job before starting an image build. Bicep includes a
# resource-group-derived suffix in its name, so it cannot be reconstructed here.
$armToken = az account get-access-token --subscription $SubscriptionId --resource https://management.azure.com/ --query accessToken -o tsv
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($armToken)) {
  throw "Failed to acquire an Azure management token for subscription '$SubscriptionId'."
}
$armHeaders = @{ Authorization = "Bearer $armToken" }
$jobsBasePath = "/subscriptions/$SubscriptionId/resourceGroups/$resolvedResourceGroupName/providers/Microsoft.App/jobs"
if ([string]::IsNullOrWhiteSpace($ContainerAppJobName)) {
  $jobsPayload = Invoke-RestMethod -Method GET -Uri "https://management.azure.com${jobsBasePath}?api-version=2024-03-01" -Headers $armHeaders
  if ($jobsPayload.PSObject.Properties['nextLink'] -and $jobsPayload.nextLink) {
    throw "Container App Job list is incomplete in resource group '$resolvedResourceGroupName'. Pass -ContainerAppJobName."
  }
  $jobs = @($jobsPayload.value)
  $matchingJobs = @($jobs | Where-Object {
      $tags = if ($_.PSObject.Properties['tags']) { $_.tags } else { $null }
      $tags -and $tags.PSObject.Properties['environment'] -and
      $tags.PSObject.Properties['managedBy'] -and
      $tags.PSObject.Properties['workload'] -and
      $tags.environment -eq $EnvironmentName.ToLower() -and
      $tags.managedBy -eq 'azd' -and $tags.workload -eq 'maester'
    })
  if ($matchingJobs.Count -eq 1) {
    $ContainerAppJobName = $matchingJobs[0].name
  }
  else {
    throw "Could not identify one Maester Container App Job in resource group '$resolvedResourceGroupName'. Pass -ContainerAppJobName."
  }
}
if ($ContainerAppJobName -notmatch '^[a-zA-Z0-9][a-zA-Z0-9-]*$') {
  throw "Invalid Container App Job name '$ContainerAppJobName'."
}
$jobPath = "${jobsBasePath}/${ContainerAppJobName}?api-version=2024-03-01"
try {
  $jobPayload = Invoke-RestMethod -Method GET -Uri "https://management.azure.com$jobPath" -Headers $armHeaders
}
catch {
  throw "Failed to read Container App Job '$ContainerAppJobName': $($_.Exception.Message)"
}
if (-not $jobPayload -or -not $jobPayload.properties.template.containers) {
  throw "Container App Job '$ContainerAppJobName' has no container template."
}

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

# Resolve the just-built tag to an immutable manifest before updating the job.
$imageDigest = (& az acr manifest show-metadata `
  --registry $acrName `
  --name "maester:${ImageTag}" `
  --subscription $SubscriptionId `
  --query digest `
  --output tsv `
  --only-show-errors) -join ''
if ($LASTEXITCODE -ne 0 -or $imageDigest -notmatch '^sha256:[a-fA-F0-9]{64}$') {
  throw "ACR did not return a valid digest for newly built image 'maester:${ImageTag}'."
}
$imageFqdn = "${acrLoginServer}/maester@$imageDigest"

# Update the Container App Job to use the ACR image
Write-Host "Updating Container App Job '$ContainerAppJobName' to use image '$imageFqdn'..."
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
} | ConvertTo-Json -Depth 30 -Compress

try {
  Invoke-RestMethod -Method PUT -Uri "https://management.azure.com$jobPath" -Headers $armHeaders -Body $updateBody -ContentType 'application/json' | Out-Null
}
catch {
  throw "Failed to update Container App Job image: $($_.Exception.Message)"
}

Write-Host "Container App Job '$ContainerAppJobName' updated to image '$imageFqdn'."
