[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'vendor\Azd.MaesterHooks\Maester-PreDownCleanup.psm1') -Force

Invoke-MaesterStandardPreDownCleanup -ManagedIdentityPrincipalEnvName 'CONTAINER_JOB_MI_PRINCIPAL_ID'
