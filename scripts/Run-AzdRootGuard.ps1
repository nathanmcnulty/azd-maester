[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$solutions = @(
  'automation-account'
  'container-app-job'
  'function-app'
  'azure-devops'
)

Write-Host ''
Write-Host 'This template repository contains multiple azd solutions.' -ForegroundColor Yellow
Write-Host 'Run azd commands from one of these folders:' -ForegroundColor Yellow
Write-Host ''

foreach ($solution in $solutions) {
  Write-Host "  cd $solution" -ForegroundColor Cyan
  Write-Host '  azd up' -ForegroundColor Cyan
  Write-Host ''
}

throw "No deployable infra is defined at the repository root. Choose a solution folder and rerun 'azd up'."
