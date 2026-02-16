[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$EnvironmentName,

  [Parameter(Mandatory = $false)]
  [switch]$KeepEnvironment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot

Write-Host "Selecting azd environment '$EnvironmentName'"
& azd env select $EnvironmentName
if ($LASTEXITCODE -ne 0) {
  throw "Failed to select azd environment '$EnvironmentName'."
}

$resourceGroupName = $null
$envValues = & azd env get-values
if ($LASTEXITCODE -eq 0) {
  foreach ($line in $envValues) {
    if ($line -like 'AZURE_RESOURCE_GROUP=*') {
      $resourceGroupName = $line.Split('=', 2)[1].Trim('"')
      break
    }
  }
}

if (-not [string]::IsNullOrWhiteSpace($resourceGroupName)) {
  Write-Host "Removing resource locks in '$resourceGroupName' (if any)..."
  $lockIdsRaw = & az lock list --resource-group $resourceGroupName --query '[].id' -o tsv
  if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($lockIdsRaw)) {
    $lockIds = @($lockIdsRaw -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    foreach ($lockId in $lockIds) {
      & az lock delete --ids $lockId | Out-Null
    }
  }
}

if ($KeepEnvironment) {
  Write-Host 'Running azd down and keeping local environment files.'
  & azd down --force --no-prompt
}
else {
  Write-Host 'Running azd down and purging local environment files.'
  & azd down --force --purge --no-prompt
}

if ($LASTEXITCODE -ne 0) {
  throw 'azd down failed.'
}

Write-Host "Environment removal completed for '$EnvironmentName'."