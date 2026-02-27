[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\shared\scripts\Maester-PreUp.psm1') -Force

Invoke-MaesterPreUp
