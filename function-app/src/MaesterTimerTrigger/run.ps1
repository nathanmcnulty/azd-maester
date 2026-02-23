# MaesterTimerTrigger/run.ps1
# Timer-triggered Azure Function that runs Maester assessments.
# Reads configuration from Function App application settings (environment variables).

param($Timer)

$ErrorActionPreference = 'Continue'
$ConfirmPreference = 'None'

# Global stopwatch for timing diagnostics
$script:sw = [System.Diagnostics.Stopwatch]::StartNew()

function Write-Step {
  param([Parameter(Mandatory = $true)][string]$Message)
  $elapsed = $script:sw.Elapsed.ToString('mm\:ss')
  Write-Output "[$elapsed] $Message"
}

function ConvertTo-BoolOrDefault {
  param(
    [Parameter(Mandatory = $false)]
    [string]$Value,
    [Parameter(Mandatory = $true)]
    [bool]$Default
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return $Default
  }

  switch ($Value.Trim().ToLower()) {
    'true' { return $true }
    'false' { return $false }
    default { return $Default }
  }
}

function Get-PlainToken {
  param([Parameter(Mandatory = $true)][string]$ResourceUrl)

  $tokenResponse = Get-AzAccessToken -ResourceUrl $ResourceUrl -AsSecureString
  $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenResponse.Token)
  try { return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr) }
  finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr) }
}

function Set-BlobContent {
  param(
    [Parameter(Mandatory = $true)][string]$AccountName,
    [Parameter(Mandatory = $true)][string]$Container,
    [Parameter(Mandatory = $true)][string]$BlobName,
    [Parameter(Mandatory = $true)][string]$SourcePath,
    [Parameter(Mandatory = $true)][string]$StorageToken,
    [Parameter(Mandatory = $true)][string]$ContentType,
    [string]$AccessTier = 'Cool',
    [string]$ContentEncoding
  )

  $uri = "https://$AccountName.blob.core.windows.net/$Container/$BlobName"
  $headers = @{
    'Authorization'    = "Bearer $StorageToken"
    'x-ms-version'     = '2021-12-02'
    'x-ms-blob-type'   = 'BlockBlob'
    'x-ms-access-tier' = $AccessTier
  }

  if (-not [string]::IsNullOrWhiteSpace($ContentEncoding)) {
    $headers['x-ms-blob-content-encoding'] = $ContentEncoding
  }

  Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -InFile $SourcePath -ContentType $ContentType -ErrorAction Stop | Out-Null
}

function Compress-GzipFile {
  param(
    [Parameter(Mandatory = $true)][string]$InputPath,
    [Parameter(Mandatory = $true)][string]$OutputPath
  )

  $inputStream = [System.IO.File]::OpenRead($InputPath)
  try {
    $outputStream = [System.IO.File]::Create($OutputPath)
    try {
      $gzipStream = [System.IO.Compression.GzipStream]::new($outputStream, [System.IO.Compression.CompressionMode]::Compress)
      try {
        $inputStream.CopyTo($gzipStream)
      }
      finally {
        $gzipStream.Dispose()
      }
    }
    finally {
      $outputStream.Dispose()
    }
  }
  finally {
    $inputStream.Dispose()
  }
}

function Publish-WebAppContent {
  param(
    [Parameter(Mandatory = $true)][string]$AppName,
    [Parameter(Mandatory = $true)][string]$AppResourceGroupName,
    [Parameter(Mandatory = $true)][string]$SourcePath
  )

  $armToken = Get-PlainToken -ResourceUrl 'https://management.azure.com/'
  $kuduHeaders = @{
    'Authorization' = "Bearer $armToken"
    'If-Match'      = '*'
  }

  $kuduUri = "https://$AppName.scm.azurewebsites.net/api/vfs/site/wwwroot/index.html"
  Invoke-RestMethod -Method Put -Uri $kuduUri -Headers $kuduHeaders -InFile $SourcePath -ContentType 'text/html' | Out-Null

  Write-Output "Published latest report to Web App '$AppName' as index.html"
}

function Test-ModuleInstalled {
  param(
    [Parameter(Mandatory = $true)][string]$ModuleName,
    [Parameter(Mandatory = $false)][string]$MaxMajorVersion
  )

  # Managed dependencies (requirements.psd1) should already provide these modules.
  # This check is a runtime fallback only – Install-Module downloads to ephemeral
  # local disk and is lost on Consumption-plan cold starts, so it should not be the
  # primary installation mechanism.
  if (Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue) {
    return
  }

  Write-Warning "Module '$ModuleName' was not found via managed dependencies. Attempting runtime Install-Module as fallback (this may consume significant execution time)."
  $installArgs = @{
    Name            = $ModuleName
    Force           = $true
    Scope           = 'CurrentUser'
    Repository      = 'PSGallery'
    AllowClobber    = $true
    ErrorAction     = 'Stop'
  }
  if (-not [string]::IsNullOrWhiteSpace($MaxMajorVersion)) {
    $installArgs['MaximumVersion'] = "$MaxMajorVersion.999.999"
  }
  Install-Module @installArgs
}

# ──────────────────────────────────────────────
# Read configuration from app settings
# ──────────────────────────────────────────────

Write-Step "Starting Maester function trigger"

if ($Timer.IsPastDue) {
  Write-Step 'Timer trigger is past due. Running immediately.'
}

try {

Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue

$StorageAccountName = $env:STORAGE_ACCOUNT_NAME
$includeExchange = ConvertTo-BoolOrDefault -Value $env:INCLUDE_EXCHANGE -Default $false
$includeTeams = ConvertTo-BoolOrDefault -Value $env:INCLUDE_TEAMS -Default $false
$includeAzure = ConvertTo-BoolOrDefault -Value $env:INCLUDE_AZURE -Default $false
$MailRecipient = $env:MAIL_RECIPIENT
$WebAppName = $env:WEB_APP_NAME
$WebAppResourceGroupName = $env:WEB_APP_RESOURCE_GROUP_NAME
$ExportContainer = 'archive'
$DashboardContainer = 'latest'

Write-Step "Config: Exchange=$includeExchange, Teams=$includeTeams, Azure=$includeAzure, Storage=$StorageAccountName"

# Install optional modules not handled by managed dependencies
$optionalModules = @()
if ($includeExchange) {
  $optionalModules += @{ Name = 'ExchangeOnlineManagement'; MaxMajor = '3' }
}
if ($includeTeams) {
  $optionalModules += @{ Name = 'MicrosoftTeams'; MaxMajor = '6' }
}

foreach ($mod in $optionalModules) {
  Write-Step "Checking module: $($mod.Name)"
  Test-ModuleInstalled -ModuleName $mod.Name -MaxMajorVersion $mod.MaxMajor
}

# ──────────────────────────────────────────────
# Authenticate and connect
# ──────────────────────────────────────────────

Write-Step 'Importing core modules'
Import-Module Az.Accounts -Force -ErrorAction Stop
Import-Module Microsoft.Graph.Authentication -Force -ErrorAction Stop
Import-Module Maester -Force -ErrorAction Stop
Import-Module Pester -Force -ErrorAction Stop
Write-Step 'Core modules imported'

# Ensure context autosave is disabled (profile.ps1 should do this, but guard against
# edge cases where the profile check did not fire).
Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null

# Connect with managed identity (profile.ps1 may already have done this)
$azCtx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $azCtx) {
  Write-Step 'No Az context found. Connecting with managed identity...'
  Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
}
else {
  Write-Step "Az context already established (Account: $($azCtx.Account.Id))"
}

Write-Step 'Connecting to Microsoft Graph with managed identity'
Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop | Out-Null
Write-Step 'Microsoft Graph connection established'

$tenantId = $null
try {
  $ctx = Get-MgContext
  if ($ctx -and $ctx.TenantId) {
    $tenantId = $ctx.TenantId
  }
}
catch {
}

$moera = $null
if ($includeExchange) {
  Write-Step 'IncludeExchange enabled. Attempting Exchange Online connection using managed identity.'
  try {
    Import-Module ExchangeOnlineManagement -Force

    # Resolve tenant initial domain (MOERA) for Organization parameter
    try {
      $domains = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/domains'
      if ($domains -and $domains.value) {
        $initial = @($domains.value | Where-Object { $_.isInitial -eq $true }) | Select-Object -First 1
        if ($initial -and $initial.id) {
          $moera = $initial.id
          Write-Step "Resolved MOERA domain: $moera"
        }
      }
    }
    catch {
      Write-Warning ("Could not resolve tenant initial domain for Exchange. Error: {0}" -f $_.Exception.Message)
    }

    # Retry Exchange connection with backoff to handle permission replication delays.
    # After initial provisioning, Exchange.ManageAsApp and View-Only Configuration
    # role assignments can take 10-30+ minutes to propagate.
    $exoConnected = $false
    $exoMaxAttempts = 3
    $exoRetryDelay = 10
    for ($exoAttempt = 1; $exoAttempt -le $exoMaxAttempts; $exoAttempt++) {
      try {
        Write-Step "Exchange connection attempt $exoAttempt/$exoMaxAttempts"
        try {
          Connect-ExchangeOnline -ManagedIdentity -ShowBanner:$false | Out-Null
        }
        catch {
          if ($moera) {
            Write-Step "Retrying Exchange connection with Organization parameter"
            Connect-ExchangeOnline -ManagedIdentity -Organization $moera -ShowBanner:$false | Out-Null
          }
          else {
            throw
          }
        }
        $exoConnected = $true
        Write-Step 'Exchange Online connection established.'
        break
      }
      catch {
        if ($exoAttempt -lt $exoMaxAttempts) {
          Write-Warning ("Exchange Online connection attempt {0}/{1} failed: {2}. Retrying in {3}s (permissions may still be replicating)..." -f $exoAttempt, $exoMaxAttempts, $_.Exception.Message, $exoRetryDelay)
          Start-Sleep -Seconds $exoRetryDelay
          $exoRetryDelay = [Math]::Min($exoRetryDelay * 2, 30)
        }
        else {
          Write-Warning ("Exchange Online connection failed after {0} attempts. Exchange-related tests will be skipped. Last error: {1}" -f $exoMaxAttempts, $_.Exception.Message)
        }
      }
    }

    # Connect to Security & Compliance PowerShell (IPPS) using managed identity
    if ($exoConnected) {
      try {
        Write-Step 'Connecting to Security & Compliance (IPPS)'
        $ippsConnectionUri = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
        $ippsConnectArgs = @{
          ManagedIdentity = $true
          ConnectionUri   = $ippsConnectionUri
          ShowBanner      = $false
        }
        if ($moera) {
          $ippsConnectArgs['Organization'] = $moera
        }
        Connect-ExchangeOnline @ippsConnectArgs | Out-Null
        Write-Step 'Security & Compliance (IPPS) connection established.'
      }
      catch {
        Write-Warning ("Security & Compliance (IPPS) connection failed. Compliance-related tests may be skipped. Error: {0}" -f $_.Exception.Message)
      }
    }
  }
  catch {
    Write-Warning ("Exchange Online setup failed. Exchange-related tests will be skipped. Error: {0}" -f $_.Exception.Message)
  }
}

if ($includeTeams) {
  Write-Step 'IncludeTeams enabled. Attempting Microsoft Teams connection using managed identity.'

  # Retry Teams connection with backoff to handle Entra directory role replication delays.
  $teamsConnected = $false
  $teamsMaxAttempts = 3
  $teamsRetryDelay = 10
  for ($teamsAttempt = 1; $teamsAttempt -le $teamsMaxAttempts; $teamsAttempt++) {
    try {
      Write-Step "Teams connection attempt $teamsAttempt/$teamsMaxAttempts"
      Import-Module MicrosoftTeams -Force
      try {
        Connect-MicrosoftTeams -Identity | Out-Null
      }
      catch {
        if ($tenantId) {
          Write-Step "Retrying Teams connection with TenantId parameter"
          Connect-MicrosoftTeams -Identity -TenantId $tenantId | Out-Null
        }
        else {
          throw
        }
      }
      $teamsConnected = $true
      Write-Step 'Microsoft Teams connection established.'
      break
    }
    catch {
      if ($teamsAttempt -lt $teamsMaxAttempts) {
        Write-Warning ("Microsoft Teams connection attempt {0}/{1} failed: {2}. Retrying in {3}s (permissions may still be replicating)..." -f $teamsAttempt, $teamsMaxAttempts, $_.Exception.Message, $teamsRetryDelay)
        Start-Sleep -Seconds $teamsRetryDelay
        $teamsRetryDelay = [Math]::Min($teamsRetryDelay * 2, 30)
      }
      else {
        Write-Warning ("Microsoft Teams connection failed after {0} attempts. Teams-related tests will be skipped. Last error: {1}" -f $teamsMaxAttempts, $_.Exception.Message)
      }
    }
  }
}

if ($includeAzure) {
  Write-Step 'IncludeAzure enabled. Azure connection is already established via Connect-AzAccount -Identity.'
}

# ──────────────────────────────────────────────
# Run Maester tests
# ──────────────────────────────────────────────

$tempBase = [System.IO.Path]::GetTempPath()
$tempRoot = Join-Path -Path $tempBase -ChildPath ("maester-{0}" -f (Get-Date -Format 'yyyyMMddHHmmss'))
New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null
Write-Step "Temp output folder: $tempRoot"

$maesterModule = Get-Module -Name Maester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
if (-not $maesterModule) {
  throw 'Maester module was not found after import.'
}
Write-Step "Maester module version: $($maesterModule.Version) at $($maesterModule.ModuleBase)"

$moduleRoot = Split-Path -Path $maesterModule.Path -Parent
$testsCandidates = @(
  (Join-Path -Path $moduleRoot -ChildPath 'maester-tests')
  (Join-Path -Path $moduleRoot -ChildPath 'tests')
)

$testsPath = $null
foreach ($candidate in $testsCandidates) {
  if (-not (Test-Path -Path $candidate -PathType Container)) {
    continue
  }

  $testFile = Get-ChildItem -Path $candidate -Recurse -Filter '*.Tests.ps1' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($testFile) {
    $testsPath = $candidate
    break
  }
}

if (-not $testsPath) {
  throw "Could not locate Maester test files under module path '$moduleRoot'."
}

Write-Step "Using Maester test path: $testsPath"

$testFileCount = (Get-ChildItem -Path $testsPath -Recurse -Filter '*.Tests.ps1' -ErrorAction SilentlyContinue).Count
Write-Step "Found $testFileCount test file(s)"

$pesterConfig = [PesterConfiguration]@{
  TestRegistry = @{
    Enabled = $false
  }
}

$maesterInvokeParameters = @{
  Path                = $testsPath
  OutputFolder        = $tempRoot
  NonInteractive      = $true
  PesterConfiguration = $pesterConfig
}

if (-not [string]::IsNullOrWhiteSpace($MailRecipient)) {
  $maesterInvokeParameters['MailRecipient'] = $MailRecipient
  $maesterInvokeParameters['MailUserId'] = $MailRecipient
  Write-Output "Email notifications enabled for recipient: $MailRecipient"
}

Write-Step "Running Invoke-Maester from test path '$testsPath'"
try {
  Invoke-Maester @maesterInvokeParameters
}
catch {
  Write-Warning "Invoke-Maester encountered an error: $($_.Exception.Message)"
}
Write-Step 'Invoke-Maester execution completed'

# ──────────────────────────────────────────────
# Locate generated report
# ──────────────────────────────────────────────

$generatedHtml = Get-ChildItem -Path $tempRoot -Recurse -Filter '*.html' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($generatedHtml) {
  $outputHtmlPath = $generatedHtml.FullName
  Write-Step "Using generated HTML report: $outputHtmlPath (size: $([math]::Round($generatedHtml.Length/1KB, 1)) KB)"
}
else {
  $outputHtmlPath = Join-Path -Path $tempRoot -ChildPath 'MaesterReport.html'
  $fallbackHtml = @"
<html><body><h1>Maester Run Completed</h1><p>No HTML report was generated by Invoke-Maester in this execution.</p><p>Timestamp: $(Get-Date -Format 'u')</p></body></html>
"@
  Set-Content -Path $outputHtmlPath -Value $fallbackHtml -Encoding utf8
  Write-Warning "No HTML output was generated by Invoke-Maester. Created fallback report at $outputHtmlPath"
}

Write-Step 'Maester run completed. Report generated successfully.'

# ──────────────────────────────────────────────
# Upload results to storage
# ──────────────────────────────────────────────

if (-not [string]::IsNullOrWhiteSpace($StorageAccountName)) {
  Write-Step 'Acquiring storage token'
  $storageToken = Get-PlainToken -ResourceUrl 'https://storage.azure.com/'
  $timestamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'

  $datedArchiveBlob = "maester-report-$timestamp.html.gz"
  $compressedArchivePath = Join-Path -Path $tempRoot -ChildPath $datedArchiveBlob
  try {
    Write-Step "Uploading archive blob: $datedArchiveBlob"
    Compress-GzipFile -InputPath $outputHtmlPath -OutputPath $compressedArchivePath
    Set-BlobContent -AccountName $StorageAccountName -Container $ExportContainer -BlobName $datedArchiveBlob -SourcePath $compressedArchivePath -StorageToken $storageToken -ContentType 'application/gzip' -AccessTier 'Cool' -ContentEncoding 'gzip'
    Write-Step "Uploaded archived report (gzip): $datedArchiveBlob"
  }
  catch {
    Write-Warning "Archive upload failed: $($_.Exception.Message)"
  }

  try {
    Write-Step 'Uploading latest.html'
    Set-BlobContent -AccountName $StorageAccountName -Container $DashboardContainer -BlobName 'latest.html' -SourcePath $outputHtmlPath -StorageToken $storageToken -ContentType 'text/html' -AccessTier 'Cool'
    Write-Step 'Uploaded latest report pointer: latest.html'
  }
  catch {
    Write-Warning "Latest report upload failed: $($_.Exception.Message)"
  }
}

# ──────────────────────────────────────────────
# Publish to web app (optional)
# ──────────────────────────────────────────────

if (-not [string]::IsNullOrWhiteSpace($WebAppName) -and -not [string]::IsNullOrWhiteSpace($WebAppResourceGroupName)) {
  Write-Step "Publishing report to Web App '$WebAppName'"
  Publish-WebAppContent -AppName $WebAppName -AppResourceGroupName $WebAppResourceGroupName -SourcePath $outputHtmlPath
}
elseif (-not [string]::IsNullOrWhiteSpace($WebAppName)) {
  Write-Warning "WEB_APP_NAME is set to '$WebAppName' but WEB_APP_RESOURCE_GROUP_NAME is missing. Skipping Web App content publish."
}

Write-Step "Function trigger completed successfully"

}
catch {
  Write-Step "FATAL ERROR: $($_.Exception.Message)"
  Write-Step "Error details: $($_.ScriptStackTrace)"
  throw
}
