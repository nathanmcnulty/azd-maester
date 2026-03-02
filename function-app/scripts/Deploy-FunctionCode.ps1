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

# Create a staging copy so we can inject optional managed dependencies
# without modifying the source tree
$stagingPath = Join-Path -Path $env:TEMP -ChildPath "func-staging-$(Get-Date -Format 'yyyyMMddHHmmss')"
Copy-Item -Path $srcPath -Destination $stagingPath -Recurse -Force

# Dynamically add optional modules to requirements.psd1 so they are installed
# as managed dependencies (cached in Azure Files) instead of at runtime via
# Install-Module (ephemeral local disk, lost on every cold start).
$optionalModules = [ordered]@{}
if ($IncludeExchange) {
  $optionalModules['ExchangeOnlineManagement'] = '3.*'
}
if ($IncludeTeams) {
  $optionalModules['MicrosoftTeams'] = '6.*'
}

if ($optionalModules.Count -gt 0) {
  $reqPath = Join-Path -Path $stagingPath -ChildPath 'requirements.psd1'
  $reqContent = Get-Content -Path $reqPath -Raw

  $insertionEntries = @()
  foreach ($entry in $optionalModules.GetEnumerator()) {
    $moduleName = $entry.Key
    $moduleVersion = $entry.Value
    if ($reqContent -notmatch [regex]::Escape("'$moduleName'")) {
      $insertionEntries += "    '$moduleName'$((' ' * [Math]::Max(1, 37 - $moduleName.Length)))= '$moduleVersion'"
    }
  }

  if ($insertionEntries.Count -gt 0) {
    # Insert before the closing brace of the hashtable
    $insertionBlock = ($insertionEntries -join "`n") + "`n"
    $reqContent = $reqContent -replace '(\r?\n)\}', "`n$insertionBlock}"
    Set-Content -Path $reqPath -Value $reqContent -Encoding utf8 -NoNewline
    Write-Host "Added managed dependencies: $($optionalModules.Keys -join ', ')"
  }
}

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

# FC1 (Flex Consumption): managed dependencies are not supported on Linux Legion workers.
# Disable managedDependency in host.json, clear requirements.psd1, and bundle all
# required modules directly into the Modules/ folder of the deployment package.
if ($Plan -eq 'FC1') {
  Write-Host 'FC1 plan: disabling managed dependencies and bundling modules directly.'

  if (Test-Path -Path $hostJsonPath) {
    $hostJson = Get-Content -Path $hostJsonPath -Raw | ConvertFrom-Json
    $hostJson.managedDependency = [pscustomobject]@{ enabled = $false }
    $hostJson | ConvertTo-Json -Depth 10 | Set-Content -Path $hostJsonPath -Encoding utf8
    Write-Host 'Disabled managedDependency in host.json for FC1.'
  }

  $reqPath = Join-Path -Path $stagingPath -ChildPath 'requirements.psd1'
  Set-Content -Path $reqPath -Value '@{}' -Encoding utf8
  Write-Host 'Cleared requirements.psd1 for FC1 (modules will be bundled).'

  $modulesPath = Join-Path -Path $stagingPath -ChildPath 'Modules'
  New-Item -ItemType Directory -Path $modulesPath -Force | Out-Null

  $modulesToBundle = [System.Collections.Generic.List[string]]@(
    'Az.Accounts', 'Microsoft.Graph.Authentication', 'Maester', 'Pester', 'DnsClient-PS'
  )
  if ($IncludeExchange) { $modulesToBundle.Add('ExchangeOnlineManagement') }
  if ($IncludeTeams)    { $modulesToBundle.Add('MicrosoftTeams') }

  foreach ($moduleName in $modulesToBundle) {
    Write-Host "Saving module '$moduleName' to bundle..."
    try {
      Save-Module -Name $moduleName -Path $modulesPath -Repository PSGallery -Force -AcceptLicense -ErrorAction Stop
      Write-Host "  Saved '$moduleName'." -ForegroundColor Green
    } catch {
      Write-Warning "  Failed to save module '${moduleName}': $($_.Exception.Message)"
    }
  }
}

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
    --output none 2>&1
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
