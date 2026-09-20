[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\vendor\Azd.MaesterHooks\Maester-PreUp.psm1') -Force

Invoke-MaesterPreUp
