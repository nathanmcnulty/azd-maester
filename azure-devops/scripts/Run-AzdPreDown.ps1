[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'vendor\Azd.MaesterHooks\Maester-PreDownCleanup.psm1') -Force

Invoke-MaesterAzureDevOpsPreDownCleanup
