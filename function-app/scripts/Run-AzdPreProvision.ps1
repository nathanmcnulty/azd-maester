[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$TenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\shared\scripts\Maester-PreProvision.psm1') -Force

Invoke-MaesterPreProvision `
  -SolutionName 'function-app' `
  -SubscriptionId $SubscriptionId `
  -TenantId $TenantId `
  -Location $env:AZURE_LOCATION
