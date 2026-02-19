# Invoke-MaesterContainerJob.ps1
# Runner script for the Container App Job. Mounted via Azure Files volume.
# Reads configuration from environment variables set on the Container App Job.

# Use 'Continue' globally so that test framework errors (Pester/Maester) do not
# abort the script. Critical sections use explicit -ErrorAction Stop instead.
$ErrorActionPreference = 'Continue'
$ConfirmPreference = 'None'

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
    'Authorization'  = "Bearer $StorageToken"
    'x-ms-version'   = '2021-12-02'
    'x-ms-blob-type' = 'BlockBlob'
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

  # Use ARM bearer token for Kudu VFS API (works with SCM basic auth disabled)
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
    [Parameter(Mandatory = $true)][string]$ModuleName
  )

  if (Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue) {
    return
  }

  Write-Output "Installing module '$ModuleName'..."
  Install-Module -Name $ModuleName -Force -Scope CurrentUser -Repository PSGallery -AllowClobber -ErrorAction Stop
}

# ──────────────────────────────────────────────
# Bootstrap: install required modules if not already in the image
# ──────────────────────────────────────────────

Write-Output "Starting Maester container job at $(Get-Date -Format 'u')"

Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue

$requiredModules = @(
  'Az.Accounts',
  'Microsoft.Graph.Authentication',
  'Maester',
  'Pester'
)

# Read config from environment variables
$StorageAccountName = $env:STORAGE_ACCOUNT_NAME
$includeExchange = ConvertTo-BoolOrDefault -Value $env:INCLUDE_EXCHANGE -Default $false
$includeTeams = ConvertTo-BoolOrDefault -Value $env:INCLUDE_TEAMS -Default $false
$includeAzure = ConvertTo-BoolOrDefault -Value $env:INCLUDE_AZURE -Default $false
$MailRecipient = $env:MAIL_RECIPIENT
$WebAppName = $env:WEB_APP_NAME
$WebAppResourceGroupName = $env:WEB_APP_RESOURCE_GROUP_NAME
$ExportContainer = 'archive'
$DashboardContainer = 'latest'

if ($includeExchange) {
  $requiredModules += 'ExchangeOnlineManagement'
}
if ($includeTeams) {
  $requiredModules += 'MicrosoftTeams'
}

foreach ($mod in $requiredModules) {
  Test-ModuleInstalled -ModuleName $mod
}

# ──────────────────────────────────────────────
# Authenticate and connect
# ──────────────────────────────────────────────

Import-Module Az.Accounts -Force -ErrorAction Stop
Import-Module Microsoft.Graph.Authentication -Force -ErrorAction Stop
Import-Module Maester -Force -ErrorAction Stop
Import-Module Pester -Force -ErrorAction Stop

Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop | Out-Null

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
  Write-Output 'IncludeExchange enabled. Attempting Exchange Online connection using managed identity.'
  try {
    Import-Module ExchangeOnlineManagement -Force

    # Resolve tenant initial domain (MOERA) for Organization parameter
    try {
      $domains = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/domains'
      if ($domains -and $domains.value) {
        $initial = @($domains.value | Where-Object { $_.isInitial -eq $true }) | Select-Object -First 1
        if ($initial -and $initial.id) {
          $moera = $initial.id
        }
      }
    }
    catch {
    }

    try {
      Connect-ExchangeOnline -ManagedIdentity -ShowBanner:$false | Out-Null
    }
    catch {
      if ($moera) {
        Connect-ExchangeOnline -ManagedIdentity -Organization $moera -ShowBanner:$false | Out-Null
      }
      else {
        throw
      }
    }

    Write-Output 'Exchange Online connection established.'

    # Connect to Security & Compliance PowerShell (IPPS) using managed identity
    try {
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
      Write-Output 'Security & Compliance (IPPS) connection established.'
    }
    catch {
      Write-Warning ("Security & Compliance (IPPS) connection failed. Compliance-related tests may be skipped. Error: {0}" -f $_.Exception.Message)
    }
  }
  catch {
    Write-Warning ("Exchange Online connection failed. Exchange-related tests may be skipped. Error: {0}" -f $_.Exception.Message)
  }
}

if ($includeTeams) {
  Write-Output 'IncludeTeams enabled. Attempting Microsoft Teams connection using managed identity.'
  try {
    Import-Module MicrosoftTeams -Force
    try {
      Connect-MicrosoftTeams -Identity | Out-Null
    }
    catch {
      if ($tenantId) {
        Connect-MicrosoftTeams -Identity -TenantId $tenantId | Out-Null
      }
      else {
        throw
      }
    }
    Write-Output 'Microsoft Teams connection established.'
  }
  catch {
    Write-Warning ("Microsoft Teams connection failed. Teams-related tests may be skipped. Error: {0}" -f $_.Exception.Message)
  }
}

if ($includeAzure) {
  Write-Output 'IncludeAzure enabled. Azure connection is already established via Connect-AzAccount -Identity.'
}

# ──────────────────────────────────────────────
# Run Maester tests
# ──────────────────────────────────────────────

$tempBase = if ($env:TEMP) { $env:TEMP } elseif ($env:TMPDIR) { $env:TMPDIR } else { '/tmp' }
$tempRoot = Join-Path -Path $tempBase -ChildPath ("maester-{0}" -f (Get-Date -Format 'yyyyMMddHHmmss'))
New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null

$maesterModule = Get-Module -Name Maester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
if (-not $maesterModule) {
  throw 'Maester module was not found after import.'
}

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

Write-Output "Using Maester test path: $testsPath"

$maesterInvokeParameters = @{
  Path           = $testsPath
  OutputFolder   = $tempRoot
  NonInteractive = $true
}

if (-not [string]::IsNullOrWhiteSpace($MailRecipient)) {
  $maesterInvokeParameters['MailRecipient'] = $MailRecipient
  $maesterInvokeParameters['MailUserId'] = $MailRecipient
  Write-Output "Email notifications enabled for recipient: $MailRecipient"
}

Write-Output "Running Invoke-Maester from test path '$testsPath'"
try {
  Invoke-Maester @maesterInvokeParameters
}
catch {
  Write-Warning "Invoke-Maester encountered an error: $($_.Exception.Message)"
}
Write-Output 'Invoke-Maester execution completed.'

# ──────────────────────────────────────────────
# Locate generated report
# ──────────────────────────────────────────────

$generatedHtml = Get-ChildItem -Path $tempRoot -Recurse -Filter '*.html' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($generatedHtml) {
  $outputHtmlPath = $generatedHtml.FullName
  Write-Output "Using generated HTML report: $outputHtmlPath"
}
else {
  $outputHtmlPath = Join-Path -Path $tempRoot -ChildPath 'MaesterReport.html'
  $fallbackHtml = @"
<html><body><h1>Maester Run Completed</h1><p>No HTML report was generated by Invoke-Maester in this execution.</p><p>Timestamp: $(Get-Date -Format 'u')</p></body></html>
"@
  Set-Content -Path $outputHtmlPath -Value $fallbackHtml -Encoding utf8
  Write-Warning "No HTML output was generated by Invoke-Maester. Created fallback report at $outputHtmlPath"
}

Write-Output "Maester run completed. Report generated successfully."

# ──────────────────────────────────────────────
# Upload results to storage
# ──────────────────────────────────────────────

if (-not [string]::IsNullOrWhiteSpace($StorageAccountName)) {
  $storageToken = Get-PlainToken -ResourceUrl 'https://storage.azure.com/'
  $timestamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'

  $datedArchiveBlob = "maester-report-$timestamp.html.gz"
  $compressedArchivePath = Join-Path -Path $tempRoot -ChildPath $datedArchiveBlob
  try {
    Compress-GzipFile -InputPath $outputHtmlPath -OutputPath $compressedArchivePath
    Set-BlobContent -AccountName $StorageAccountName -Container $ExportContainer -BlobName $datedArchiveBlob -SourcePath $compressedArchivePath -StorageToken $storageToken -ContentType 'application/gzip' -AccessTier 'Cool' -ContentEncoding 'gzip'
    Write-Output "Uploaded archived report (gzip): $datedArchiveBlob"
  }
  catch {
    Write-Warning "Archive upload failed: $($_.Exception.Message)"
  }

  try {
    Set-BlobContent -AccountName $StorageAccountName -Container $DashboardContainer -BlobName 'latest.html' -SourcePath $outputHtmlPath -StorageToken $storageToken -ContentType 'text/html' -AccessTier 'Cool'
    Write-Output "Uploaded latest report pointer: latest.html"
  }
  catch {
    Write-Warning "Latest report upload failed: $($_.Exception.Message)"
  }
}

# ──────────────────────────────────────────────
# Publish to web app (optional)
# ──────────────────────────────────────────────

if (-not [string]::IsNullOrWhiteSpace($WebAppName) -and -not [string]::IsNullOrWhiteSpace($WebAppResourceGroupName)) {
  Publish-WebAppContent -AppName $WebAppName -AppResourceGroupName $WebAppResourceGroupName -SourcePath $outputHtmlPath
}
elseif (-not [string]::IsNullOrWhiteSpace($WebAppName)) {
  Write-Warning "WEB_APP_NAME is set to '$WebAppName' but WEB_APP_RESOURCE_GROUP_NAME is missing. Skipping Web App content publish."
}

Write-Output "Container job finished at $(Get-Date -Format 'u')"
