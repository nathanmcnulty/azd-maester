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

# Azure Automation currently accepts a package contentLink with an incorrect
# contentHash. Verify the bytes again in the runbook before importing modules.
$runtimePackages = @{
  'Az.Accounts' = @{ Version = '5.5.3'; Sha256 = '5A8BE006E80A7CA66134DF1F28E0EAD93EF4BC437685B647B6720583CB58E615' }
  'Maester' = @{ Version = '2.2.0'; Sha256 = '8C8A9757771177BD89785262E6B38385CF5E5C19BB799E4399E77F6439AD699C' }
  'Pester' = @{ Version = '6.2.0'; Sha256 = 'E6AC7418D4F12500269AACA58AE56CF1CAAFBBF1AFA2CEC334E289D1CF50A239' }
  'NuGet' = @{ Version = '1.3.3'; Sha256 = 'FCF1A37925C235159AB1C23249F016E65456EA3A36D0EA42DB85F4F15BF7C033' }
  'PackageManagement' = @{ Version = '1.4.8.1'; Sha256 = '7E1F8A75B6BC8A83D8ABFF79F6690FC1DFBD534FD3E5733D97E19BCB5954C13E' }
  'PowerShellGet' = @{ Version = '2.2.5'; Sha256 = '6B8CEBF2A464EAEB31B0A6D627355C30D9D1899DBA0CE3BDD0D4E7AFCA148673' }
  'Microsoft.Graph.Authentication' = @{ Version = '2.41.0'; Sha256 = '42E8B7A8BBA6AFD1910510D8108C1871EE5D12C5A4818CC4C36CA406369A7AFD' }
  'ExchangeOnlineManagement' = @{ Version = '3.10.1'; Sha256 = '545FB0FDF65B96ABED37F4F5B5D7DB661276DDC7DE48A742BB6E7199AB9414A3' }
  'MicrosoftTeams' = @{ Version = '8.0.0'; Sha256 = '6AA426D37913DEE78628AD36DFC26E40161702018479F110F396712E896F2882' }
}

function Import-LockedRuntimeModule {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][hashtable]$PackageLock,
    [Parameter(Mandatory)][string]$DestinationRoot,
    [string]$PackageDirectory
  )

  if (-not $PackageLock.ContainsKey($Name)) { throw "Runtime package '$Name' is not locked." }
  $version = [string]$PackageLock[$Name].Version
  $expectedHash = [string]$PackageLock[$Name].Sha256
  if ($Name -notmatch '^[A-Za-z][A-Za-z0-9.-]*$' -or $version -notmatch '^\d+(\.\d+){1,3}$' -or
      $expectedHash -notmatch '^[A-Fa-f0-9]{64}$') { throw "Invalid runtime package lock for '$Name'." }

  $packagePath = if ($PackageDirectory) { Join-Path $PackageDirectory "$Name.$version.nupkg" }
    else { Join-Path $DestinationRoot "$Name.$version.nupkg" }
  if (-not $PackageDirectory) {
    Invoke-WebRequest -Uri "https://www.powershellgallery.com/api/v2/package/$Name/$version" -OutFile $packagePath -ErrorAction Stop
  }
  if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) { throw "Locked runtime package '$Name/$version' is missing." }
  if ((Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash -ne $expectedHash) {
    throw "Locked runtime package '$Name/$version' failed SHA-256 verification."
  }

  $target = Join-Path (Join-Path $DestinationRoot $Name) $version
  New-Item -ItemType Directory -Path $target -Force | Out-Null
  try {
    [IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $target)
    $manifest = Join-Path $target "$Name.psd1"
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw "Locked runtime package '$Name/$version' has no manifest." }
    $imported = Import-Module -Name $manifest -Force -PassThru -ErrorAction Stop |
      Where-Object { $_.Name -eq $Name -and $_.ModuleBase -eq $target -and $_.Version -eq [version]$version }
    if (-not $imported) { throw "Locked runtime package '$Name/$version' was not imported from its verified path." }
  }
  catch {
    Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
    throw
  }
  if (-not $PackageDirectory) { Remove-Item -LiteralPath $packagePath -Force }
}

$verifiedModuleRoot = Join-Path ([IO.Path]::GetTempPath()) "maester-verified-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $verifiedModuleRoot -Force | Out-Null
$env:PSModulePath = "$verifiedModuleRoot$([IO.Path]::PathSeparator)$env:PSModulePath"

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
  Invoke-RestMethod -Method Put -Uri $kuduUri -Headers $kuduHeaders -InFile $SourcePath -ContentType 'text/html' -ErrorAction Stop | Out-Null

  Write-Output "Published latest report to Web App '$AppName' as index.html"
}

Write-Output "Starting Maester automation runbook at $(Get-Date -Format 'u')"

foreach ($name in @('NuGet', 'PackageManagement', 'PowerShellGet', 'Az.Accounts', 'Microsoft.Graph.Authentication', 'Pester', 'Maester')) {
  Import-LockedRuntimeModule -Name $name -PackageLock $runtimePackages -DestinationRoot $verifiedModuleRoot
}

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
  Import-LockedRuntimeModule -Name 'ExchangeOnlineManagement' -PackageLock $runtimePackages -DestinationRoot $verifiedModuleRoot
  try {

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
      Write-Warning ("Could not resolve tenant initial domain for Exchange. Error: {0}" -f $_.Exception.Message)
    }

    # Retry Exchange connection with backoff to handle permission replication delays.
    # Exchange.ManageAsApp and directory roles can take 5-30+ minutes to propagate.
    $exoConnected = $false
    $exoMaxAttempts = 3
    $exoRetryDelay = 30
    for ($exoAttempt = 1; $exoAttempt -le $exoMaxAttempts; $exoAttempt++) {
      try {
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
        $exoConnected = $true
        break
      }
      catch {
        if ($exoAttempt -lt $exoMaxAttempts) {
          Write-Warning ("Exchange Online connection attempt {0}/{1} failed: {2}. Retrying in {3}s (permissions may still be replicating)..." -f $exoAttempt, $exoMaxAttempts, $_.Exception.Message, $exoRetryDelay)
          Start-Sleep -Seconds $exoRetryDelay
          $exoRetryDelay = [Math]::Min($exoRetryDelay * 2, 120)
        }
        else {
          throw
        }
      }
    }

    if ($exoConnected) {
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
  }
  catch {
    Write-Warning ("Exchange Online connection failed. Exchange-related tests may be skipped. Error: {0}" -f $_.Exception.Message)
  }
}

if ($includeTeams) {
  Import-LockedRuntimeModule -Name 'MicrosoftTeams' -PackageLock $runtimePackages -DestinationRoot $verifiedModuleRoot
  Write-Output 'IncludeTeams enabled. Attempting Microsoft Teams connection using managed identity.'

  # Retry Teams connection with backoff to handle Entra directory role replication delays.
  $teamsMaxAttempts = 3
  $teamsRetryDelay = 30
  for ($teamsAttempt = 1; $teamsAttempt -le $teamsMaxAttempts; $teamsAttempt++) {
    try {
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
      break
    }
    catch {
      if ($teamsAttempt -lt $teamsMaxAttempts) {
        Write-Warning ("Microsoft Teams connection attempt {0}/{1} failed: {2}. Retrying in {3}s (permissions may still be replicating)..." -f $teamsAttempt, $teamsMaxAttempts, $_.Exception.Message, $teamsRetryDelay)
        Start-Sleep -Seconds $teamsRetryDelay
        $teamsRetryDelay = [Math]::Min($teamsRetryDelay * 2, 120)
      }
      else {
        Write-Warning ("Microsoft Teams connection failed after {0} attempts. Teams-related tests will be skipped. Last error: {1}" -f $teamsMaxAttempts, $_.Exception.Message)
      }
    }
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

$tempRoot = Join-Path -Path $env:TEMP -ChildPath ("maester-{0}-{1}" -f (Get-Date -Format 'yyyyMMddHHmmss'), [guid]::NewGuid().ToString('N'))
New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null

$maesterModule = Get-Module -Name Maester |
  Where-Object { $_.Version -eq [version]'2.2.0' -and $_.Path.StartsWith($verifiedModuleRoot, [StringComparison]::OrdinalIgnoreCase) } |
  Select-Object -First 1
if (-not $maesterModule) {
  throw 'Maester module version 2.2.0 was not found after import.'
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

Write-Output "Running Invoke-Maester from test path '$testsPath'"

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

try {
  $ErrorActionPreference = 'Continue'
  Invoke-Maester @maesterInvokeParameters
}
catch {
  throw "Invoke-Maester failed: $($_.Exception.Message)"
}
finally {
  $ErrorActionPreference = 'Stop'
}
Write-Output 'Invoke-Maester execution completed.'

$generatedHtml = Get-ChildItem -Path $tempRoot -Recurse -Filter '*.html' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($generatedHtml -and $generatedHtml.Length -gt 0) {
  $outputHtmlPath = $generatedHtml.FullName
  Write-Output "Using generated HTML report: $outputHtmlPath"
}
else {
  throw 'Invoke-Maester did not generate a nonempty HTML report.'
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
    throw "Latest report upload failed: $($_.Exception.Message)"
  }
}

# ──────────────────────────────────────────────
# Publish to web app (optional)
# ──────────────────────────────────────────────

if (-not [string]::IsNullOrWhiteSpace($WebAppName) -and -not [string]::IsNullOrWhiteSpace($WebAppResourceGroupName)) {
  Publish-WebAppContent -AppName $WebAppName -AppResourceGroupName $WebAppResourceGroupName -SourcePath $outputHtmlPath
}
elseif (-not [string]::IsNullOrWhiteSpace($WebAppName)) {
  Write-Warning "WebAppName is set to '$WebAppName' but WebAppResourceGroupName is missing. Skipping Web App content publish."
}

Write-Output "Runbook finished at $(Get-Date -Format 'u')"
