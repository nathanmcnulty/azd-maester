[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\shared\scripts\Maester-PreDownCleanup.psm1') -Force

Invoke-MaesterStandardPreDownCleanup -ManagedIdentityPrincipalEnvName 'FUNCTION_APP_MI_PRINCIPAL_ID'
