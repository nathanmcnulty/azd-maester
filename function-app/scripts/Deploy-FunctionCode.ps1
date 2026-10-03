[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$FunctionAppName,

  [Parameter(Mandatory = $false)]
  [switch]$IncludeExchange,

  [Parameter(Mandatory = $false)]
  [switch]$IncludeTeams,

  [Parameter(Mandatory = $false)]
  [ValidateSet('FC1', 'B1', 'Y1')]
  [string]$Plan = 'FC1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$srcPath = Join-Path -Path $projectRoot -ChildPath 'src'

if (-not (Test-Path -Path $srcPath -PathType Container)) {
  throw "Function app source directory was not found: $srcPath"
}

$requiredFiles = @('host.json', 'requirements.psd1', 'profile.ps1')
foreach ($file in $requiredFiles) {
  $filePath = Join-Path -Path $srcPath -ChildPath $file
  if (-not (Test-Path -Path $filePath)) {
    throw "Required function app file is missing: $filePath"
  }
}

$triggerPath = Join-Path -Path $srcPath -ChildPath 'MaesterTimerTrigger'
if (-not (Test-Path -Path $triggerPath -PathType Container)) {
  throw "Timer trigger function directory was not found: $triggerPath"
}

# Create a unique staging copy without modifying the source tree.
$stagingPath = Join-Path -Path $env:TEMP -ChildPath "func-staging-$([guid]::NewGuid().ToString('N'))"
Copy-Item -Path $srcPath -Destination $stagingPath -Recurse -Force

# Adjust functionTimeout in host.json based on hosting plan.
# Y1 (Consumption) maxes out at 10 minutes. B1/FC1 support longer timeouts.
$hostJsonPath = Join-Path -Path $stagingPath -ChildPath 'host.json'
if (Test-Path -Path $hostJsonPath) {
  $hostJson = Get-Content -Path $hostJsonPath -Raw | ConvertFrom-Json

  switch ($Plan) {
    'Y1' {
      # Consumption plan: max 10 minutes
      $hostJson.functionTimeout = '00:10:00'
    }
    'B1' {
      # App Service Basic (Dedicated): allow 30 minutes
      $hostJson.functionTimeout = '00:30:00'
    }
    'FC1' {
      # Flex Consumption: allow 30 minutes
      $hostJson.functionTimeout = '00:30:00'
    }
  }

  $hostJson | ConvertTo-Json -Depth 10 | Set-Content -Path $hostJsonPath -Encoding utf8
  Write-Host "Set functionTimeout to $($hostJson.functionTimeout) for plan $Plan"
}

# Bundle exact, SHA-256 verified modules for every hosting plan. Managed
# dependencies and Save-Module can otherwise drift between deployments.
$hostJson = Get-Content -LiteralPath $hostJsonPath -Raw | ConvertFrom-Json
$hostJson.managedDependency = [pscustomobject]@{ enabled = $false }
$hostJson | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $hostJsonPath -Encoding utf8
Set-Content -LiteralPath (Join-Path $stagingPath 'requirements.psd1') -Value '@{}' -Encoding utf8

$moduleNames = @('Az.Accounts', 'Microsoft.Graph.Authentication', 'Maester', 'Pester', 'DnsClient-PS')
if ($IncludeExchange) { $moduleNames += @('ExchangeOnlineManagement', 'PackageManagement', 'PowerShellGet') }
if ($IncludeTeams) { $moduleNames += 'MicrosoftTeams' }
$modulesPath = Join-Path $stagingPath 'Modules'
New-Item -ItemType Directory -Path $modulesPath -Force | Out-Null
& (Join-Path $PSScriptRoot 'Install-LockedModules.ps1') -LockPath (Join-Path $projectRoot 'runtime-packages.lock.json') -DestinationRoot $modulesPath -PackageNames $moduleNames
if (-not $?) { throw 'Locked module installer did not complete.' }

$zipFileName = "function-app-deploy-$(Get-Date -Format 'yyyyMMddHHmmss').zip"
$zipPath = Join-Path -Path $env:TEMP -ChildPath $zipFileName

Write-Host "Creating deployment package from staging directory"

if (Test-Path -Path $zipPath) {
  Remove-Item -Path $zipPath -Force
}

# Use .NET compression to create the zip reliably
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($stagingPath, $zipPath)

$zipSizeKB = [math]::Round((Get-Item $zipPath).Length / 1024, 1)
Write-Host "Deployment package created: $zipPath ($zipSizeKB KB)"

Write-Host "Deploying function code to '$FunctionAppName'..."
$maxRetries = 3
$deployed = $false
for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
  Write-Host "Zip deploy attempt $attempt of $maxRetries..."
  $deployOutput = & az functionapp deployment source config-zip `
    --subscription $SubscriptionId `
    --resource-group $ResourceGroupName `
    --name $FunctionAppName `
    --src $zipPath `
    --timeout 300 `
    --output none `
    --only-show-errors 2>&1
  foreach ($line in $deployOutput) {
    $text = if ($line -is [System.Management.Automation.ErrorRecord]) { $line.Exception.Message } else { "$line" }
    if ($text -match '^WARNING:\s*(.+)') {
      Write-Host "Deployment status: $($Matches[1])"
    } elseif ($text) {
      Write-Host $text
    }
  }
  if ($LASTEXITCODE -eq 0) {
    $deployed = $true
    break
  }
  if ($attempt -lt $maxRetries) {
    Write-Host "Zip deploy attempt $attempt failed (SCM timeout). Retrying in 30 seconds..."
    Start-Sleep -Seconds 30
  }
}
if (-not $deployed) {
  throw "Function app zip deployment failed for '$FunctionAppName' after $maxRetries attempts."
}

Write-Host "Function code deployed successfully to '$FunctionAppName'."

# Clean up temp artifacts
try {
  Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
  if (Test-Path -Path $stagingPath) {
    Remove-Item -Path $stagingPath -Recurse -Force -ErrorAction SilentlyContinue
  }
}
catch {
  Write-Verbose "Could not remove temporary deployment artifacts."
}
