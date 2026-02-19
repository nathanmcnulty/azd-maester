param(
  [Parameter(Mandatory = $false)]
  [string]$StorageAccountName,

  [Parameter(Mandatory = $false)]
  [string]$WebAppName,

  [Parameter(Mandatory = $false)]
  [string]$WebAppResourceGroupName,

  [Parameter(Mandatory = $false)]
  [string]$MailRecipient,

  [Parameter(Mandatory = $false)]
  [string]$ExportContainer = 'archive',

  [Parameter(Mandatory = $false)]
  [string]$DashboardContainer = 'latest'
)

$ErrorActionPreference = 'Stop'
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
    'Authorization' = "Bearer $StorageToken"
    'x-ms-version' = '2021-12-02'
    'x-ms-blob-type' = 'BlockBlob'
    'x-ms-access-tier' = $AccessTier
  }

  if (-not [string]::IsNullOrWhiteSpace($ContentEncoding)) {
    $headers['x-ms-blob-content-encoding'] = $ContentEncoding
  }

  Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -InFile $SourcePath -ContentType $ContentType | Out-Null
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

Write-Output "Starting Maester automation runbook at $(Get-Date -Format 'u')"

Import-Module Az.Accounts -Force
Import-Module Microsoft.Graph.Authentication -Force
Import-Module Maester -Force
Import-Module Pester -Force

Connect-AzAccount -Identity | Out-Null
Connect-MgGraph -Identity -NoWelcome | Out-Null

$tenantId = $null
try {
  $ctx = Get-MgContext
  if ($ctx -and $ctx.TenantId) {
    $tenantId = $ctx.TenantId
  }
}
catch {
}

$includeExchange = $false
$includeTeams = $false
$includeAzure = $false

try {
  $includeExchange = ConvertTo-BoolOrDefault -Value (Get-AutomationVariable -Name 'IncludeExchange') -Default $false
}
catch {
}

try {
  $includeTeams = ConvertTo-BoolOrDefault -Value (Get-AutomationVariable -Name 'IncludeTeams') -Default $false
}
catch {
}

try {
  $includeAzure = ConvertTo-BoolOrDefault -Value (Get-AutomationVariable -Name 'IncludeAzure') -Default $false
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

if (-not $StorageAccountName) {
  try {
    $StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
  }
  catch {
    Write-Warning "Automation variable 'StorageAccountName' not found. Results will stay in temporary storage only."
  }
}

if (-not $WebAppName) {
  try {
    $WebAppName = Get-AutomationVariable -Name 'WebAppName'
    if ([string]::IsNullOrWhiteSpace($WebAppName)) {
      $WebAppName = $null
    }
  }
  catch {
    Write-Verbose "Automation variable 'WebAppName' not found. Web App publishing disabled."
  }
}

if (-not $WebAppResourceGroupName) {
  try {
    $WebAppResourceGroupName = Get-AutomationVariable -Name 'WebAppResourceGroupName'
    if ([string]::IsNullOrWhiteSpace($WebAppResourceGroupName)) {
      $WebAppResourceGroupName = $null
    }
  }
  catch {
    Write-Verbose "Automation variable 'WebAppResourceGroupName' not found. Web App publishing disabled."
  }
}

if (-not $MailRecipient) {
  try {
    $MailRecipient = Get-AutomationVariable -Name 'MailRecipient'
    if ([string]::IsNullOrWhiteSpace($MailRecipient)) {
      $MailRecipient = $null
    }
  }
  catch {
    Write-Verbose "Automation variable 'MailRecipient' not found. Email notifications disabled."
  }
}

$tempRoot = Join-Path -Path $env:TEMP -ChildPath ("maester-{0}" -f (Get-Date -Format 'yyyyMMddHHmmss'))
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

$outputHtmlPath = $null
Write-Output "Running Invoke-Maester from test path '$testsPath' and discovering generated HTML output under $tempRoot"

$maesterInvokeParameters = @{
  Path           = $testsPath
  OutputFolder   = $tempRoot
  NonInteractive = $true
}

if ($MailRecipient) {
  $maesterInvokeParameters['MailRecipient'] = $MailRecipient
  $maesterInvokeParameters['MailUserId'] = $MailRecipient
  Write-Output "Email notifications enabled for recipient: $MailRecipient"
}

try {
  $ErrorActionPreference = 'Continue'
  Invoke-Maester @maesterInvokeParameters
}
catch {
  Write-Warning "Invoke-Maester encountered an error: $($_.Exception.Message)"
}
finally {
  $ErrorActionPreference = 'Stop'
}
Write-Output 'Invoke-Maester execution completed.'

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

if ($StorageAccountName) {
  $storageToken = Get-PlainToken -ResourceUrl 'https://storage.azure.com/'
  $timestamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'

  $datedArchiveBlob = "maester-report-$timestamp.html.gz"
  $compressedArchivePath = Join-Path -Path $tempRoot -ChildPath $datedArchiveBlob
  Compress-GzipFile -InputPath $outputHtmlPath -OutputPath $compressedArchivePath
  Set-BlobContent -AccountName $StorageAccountName -Container $ExportContainer -BlobName $datedArchiveBlob -SourcePath $compressedArchivePath -StorageToken $storageToken -ContentType 'application/gzip' -AccessTier 'Cool' -ContentEncoding 'gzip'
  Write-Output "Uploaded archived report (gzip): $datedArchiveBlob"

  Set-BlobContent -AccountName $StorageAccountName -Container $DashboardContainer -BlobName 'latest.html' -SourcePath $outputHtmlPath -StorageToken $storageToken -ContentType 'text/html' -AccessTier 'Cool'
  Write-Output "Uploaded latest report pointer: latest.html"
}

if ($WebAppName -and $WebAppResourceGroupName) {
  Publish-WebAppContent -AppName $WebAppName -AppResourceGroupName $WebAppResourceGroupName -SourcePath $outputHtmlPath
}
elseif ($WebAppName) {
  Write-Warning "WebAppName is set to '$WebAppName' but WebAppResourceGroupName is missing. Skipping Web App content publish."
}

Write-Output "Runbook finished at $(Get-Date -Format 'u')"
