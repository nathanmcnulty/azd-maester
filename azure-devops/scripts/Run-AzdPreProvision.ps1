[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$TenantId,

  [Parameter(Mandatory = $false)]
  [string]$EnvironmentName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $EnvironmentName) { $EnvironmentName = $env:AZURE_ENV_NAME }
if ([string]::IsNullOrWhiteSpace($EnvironmentName) -or
    ($env:AZURE_ENV_NAME -and $env:AZURE_ENV_NAME -cne $EnvironmentName)) {
  throw 'The requested azd environment does not match the hook environment.'
}
Import-Module (Join-Path $PSScriptRoot 'Resolve-DeploymentTarget.psm1') -Force
$expectedSubscriptionId = if ($SubscriptionId) { $SubscriptionId } else { $env:AZURE_SUBSCRIPTION_ID }
$expectedTenantId = if ($TenantId) { $TenantId } else { $env:AZURE_TENANT_ID }
$null = Assert-MaesterAzdSelectedEnvironment -EnvironmentName $EnvironmentName -ProjectRoot $projectRoot `
  -SubscriptionId $expectedSubscriptionId -TenantId $expectedTenantId

Import-Module (Join-Path $PSScriptRoot 'vendor\Azd.MaesterHooks\Maester-PreProvision.psm1') -Force

Invoke-MaesterPreProvision `
  -SolutionName 'azure-devops' `
  -SubscriptionId $SubscriptionId `
  -TenantId $TenantId `
  -Location $env:AZURE_LOCATION `
  -RequireGit `
  -RequireAdopsModule
