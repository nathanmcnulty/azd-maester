#Requires -Version 7.6
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
  'Maester' = @{ Version = '2.3.0'; Sha256 = '95F720822D04271F5E15F4665BC017111DC72E17B97E5D0525CB4EC2FF5BD0B0' }
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
    'x-ms-date' = [datetime]::UtcNow.ToString('R', [Globalization.CultureInfo]::InvariantCulture)
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

# BEGIN shared pure assessment health contract (Container PR #51).
# Deliberately separate framework health from policy compliance. These are two
# unconditional core tests in the locked Maester 2.3.0 suite, not a coverage claim.
$script:CoreCases = [ordered]@{
  'MT.1068' = 'Maester/Entra/Test-MtTenantCreationRestricted.Tests.ps1'
  'MT.1069' = 'Maester/Entra/Test-MtSecurityGroupCreationRestricted.Tests.ps1'
}

function Get-EvidenceCount {
  param($Value)
  if ($null -eq $Value -or $Value -is [bool] -or $Value -is [string] -or
      $Value -isnot [ValueType] -or $Value -lt 0 -or $Value -gt [int]::MaxValue -or
      [decimal]$Value -ne [math]::Truncate([decimal]$Value)) { throw 'assessment.invalidCount' }
  [int]$Value
}

function Get-MaesterAssessmentEvidence {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$Output,
    [Parameter(Mandatory)][string]$JunitPath,
    [Parameter(Mandatory)][string]$TestsPath,
    [Parameter(Mandatory)][string]$ReportPath
  )
  $ErrorActionPreference = 'Stop'
  # Ignore incidental success-stream strings, but never select one of multiple
  # result objects. No HTML/JavaScript is evaluated to recover missing evidence.
  $results = @($Output | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Tests'] })
  if ($results.Count -ne 1) { throw 'assessment.resultMissingOrAmbiguous' }
  $result = $results[0]
  if ($result.EndOfJson -isnot [string] -or $result.EndOfJson -cne 'EndOfJson' -or
      ($result.CurrentVersion -isnot [string] -and $result.CurrentVersion -isnot [version]) -or
      [string]$result.CurrentVersion -cne '2.3.0') { throw 'assessment.resultInvalid' }
  $tests = @($result.Tests)
  foreach ($test in $tests) {
    if ($null -eq $test -or $test.Result -isnot [string]) { throw 'assessment.resultInvalid' }
  }
  $counts = [ordered]@{}
  foreach ($state in 'Passed','Failed','Error','Investigate','Skipped','NotRun') {
    $name = $state + 'Count'
    $counts[$name] = Get-EvidenceCount $result.$name
    if ($counts[$name] -ne @($tests | Where-Object Result -CEQ $state).Count) { throw 'assessment.countMismatch' }
  }
  $counts.TotalCount = Get-EvidenceCount $result.TotalCount
  $sum = 0L
  foreach ($state in 'Passed','Failed','Error','Investigate','Skipped','NotRun') { $sum += $counts[$state + 'Count'] }
  if ($sum -ne $counts.TotalCount -or $tests.Count -ne $counts.TotalCount -or $sum -eq 0) { throw 'assessment.countMismatch' }
  if ($counts.ErrorCount -ne 0) { throw 'assessment.maesterErrors' }
  # Maester reclassifies only selected exception types. An IOException or a
  # mixed assertion/runtime error can still be labelled Failed (or Investigate).
  # Check every record, never only the first, using Pester's stable marker IDs.
  foreach ($test in $tests) {
    if (-not $test.PSObject.Properties['ErrorRecord']) { throw 'assessment.errorRecordsMissing' }
    $records = @($test.ErrorRecord | Where-Object { $null -ne $_ })
    $allowed = switch ($test.Result) {
      'Failed' { @('PesterAssertionFailed') }
      'Skipped' { @('PesterTestSkipped') }
      'Investigate' { @('PesterAssertionFailed','PesterTestSkipped','PesterTestInconclusive') }
      default { @() }
    }
    if ($test.Result -ceq 'Failed' -and $records.Count -eq 0) { throw 'assessment.unclassifiedFailure' }
    foreach ($record in $records) {
      if ($record.FullyQualifiedErrorId -isnot [string] -or $record.FullyQualifiedErrorId -cnotin $allowed) { throw 'assessment.unclassifiedFailure' }
    }
  }
  $core = [ordered]@{}
  foreach ($id in $script:CoreCases.Keys) {
    $matches = @($tests | Where-Object Id -CEQ $id)
    $expectedPath = [IO.Path]::GetFullPath((Join-Path $TestsPath $script:CoreCases[$id]))
    if ($matches.Count -ne 1 -or $matches[0].Result -cnotin @('Passed','Failed') -or
        [string]::IsNullOrWhiteSpace($matches[0].ScriptBlockFile) -or
        [IO.Path]::GetFullPath($matches[0].ScriptBlockFile) -cne $expectedPath) { throw 'assessment.coreNotExecuted' }
    $core[$id] = $matches[0].Result
  }
  $reader = $null
  try {
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 16777216
    $reader = [Xml.XmlReader]::Create($JunitPath, $settings)
    $document = [Xml.XmlDocument]::new()
    $document.XmlResolver = $null
    $document.Load($reader)
    $root = $document.DocumentElement
    if ($null -eq $root -or $root.get_Name() -cne 'testsuites') { throw 'assessment.junitInvalid' }
    $junit = [ordered]@{}
    foreach ($name in 'tests','errors','failures','disabled') {
      $n = 0
      if (-not $root.HasAttribute($name) -or $root.GetAttribute($name) -cnotmatch '^(0|[1-9][0-9]*)\z' -or
          -not [int]::TryParse($root.GetAttribute($name), [ref]$n)) { throw 'assessment.junitInvalid' }
      $junit[$name] = $n
    }
  }
  catch { throw 'assessment.junitInvalid' }
  finally { if ($null -ne $reader) { $reader.Dispose() } }
  # Pester 6.2.0 root errors = FailedContainersCount + FailedBlocksCount.
  # Maester can reclassify Pester failures/skips as Investigate, so do not equate
  # every Pester failure with a policy finding or reject expected exclusions.
  if ($junit.errors -ne 0) { throw 'assessment.junitErrors' }
  if ($junit.tests -ne $counts.TotalCount -or
      $junit.failures -lt $counts.FailedCount -or $junit.failures -gt ($counts.FailedCount + $counts.InvestigateCount) -or
      $junit.disabled -lt ($counts.SkippedCount + $counts.NotRunCount) -or
      $junit.disabled -gt ($counts.SkippedCount + $counts.NotRunCount + $counts.InvestigateCount) -or
      (($junit.failures - $counts.FailedCount) + ($junit.disabled - $counts.SkippedCount - $counts.NotRunCount)) -gt $counts.InvestigateCount -or
      ($junit.failures + $junit.disabled) -gt $junit.tests) { throw 'assessment.junitCountMismatch' }
  if ([string]::IsNullOrWhiteSpace($result.OutputFiles.OutputHtmlFile) -or [IO.Path]::GetFullPath($result.OutputFiles.OutputHtmlFile) -cne [IO.Path]::GetFullPath($ReportPath)) { throw 'assessment.reportMismatch' }
  if (-not (Test-Path -LiteralPath $ReportPath -PathType Leaf) -or (Get-Item -LiteralPath $ReportPath).Length -le 0) { throw 'assessment.reportMissing' }
  [ordered]@{
    Outcome = 'Completed'; Counts = $counts; CoreCases = $core
    JunitErrors = $junit.errors; JunitTests = $junit.tests
    ReportSha256 = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash.ToLowerInvariant()
    JunitSha256 = (Get-FileHash -LiteralPath $JunitPath -Algorithm SHA256).Hash.ToLowerInvariant()
  }
}

# END shared pure assessment health contract.

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
  Where-Object { $_.Version -eq [version]'2.3.0' -and $_.Path.StartsWith($verifiedModuleRoot, [StringComparison]::OrdinalIgnoreCase) } |
  Select-Object -First 1
if (-not $maesterModule) {
  throw 'Maester module version 2.3.0 was not found after import.'
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

Write-Output "Running Invoke-Maester assessment."
$outputHtmlPath = Join-Path $tempRoot 'assessment.html'
$junitPath = Join-Path $tempRoot 'pester-junit.xml'

$pesterConfig = [PesterConfiguration]@{
  Run = @{
    # Drift is not an enabled host feature; exclude it before discovery.
    ExcludePath = @((Join-Path $testsPath 'Maester/Drift/MT1060Drift.tests.ps1'))
  }
  TestResult = @{ Enabled = $true; OutputFormat = 'JUnitXml'; OutputPath = $junitPath; OutputEncoding = 'UTF8' }
  Output = @{ Verbosity = 'None' }
  TestRegistry = @{
    Enabled = $false
  }
}

$maesterInvokeParameters = @{
  Path                = $testsPath
  OutputFolder        = $tempRoot
  OutputFolderFileName = 'assessment'
  PassThru            = $true
  NonInteractive      = $true
  DisableTelemetry    = $true
  SkipVersionCheck    = $true
  PesterConfiguration = $pesterConfig
}

if (-not [string]::IsNullOrWhiteSpace($MailRecipient)) {
  $maesterInvokeParameters['MailRecipient'] = $MailRecipient
  $maesterInvokeParameters['MailUserId'] = $MailRecipient
  Write-Output 'Upstream inline email is configured; delivery is unverified.'
}

$previousDriftRoot = [Environment]::GetEnvironmentVariable('MAESTER_FOLDER_DRIFT', 'Process')
try {
  [Environment]::SetEnvironmentVariable('MAESTER_FOLDER_DRIFT', [System.Management.Automation.Language.NullString]::Value, 'Process')
  $ErrorActionPreference = 'Continue'
  # ErrorVariable also captures errors handled inside Maester/Pester (including
  # policy assertion and skip control flow). Capture only errors emitted across
  # this invocation boundary; the result/JUnit gate below still inspects every
  # test ErrorRecord and every engine error without a message/type blacklist.
  $invocationOutput = @(Invoke-Maester @maesterInvokeParameters 2>&1 3>$null 4>$null 5>$null 6>$null)
  $invocationErrors = @($invocationOutput | Where-Object { $_ -is [Management.Automation.ErrorRecord] })
  $maesterOutput = @($invocationOutput | Where-Object { $_ -isnot [Management.Automation.ErrorRecord] })
}
catch {
  throw 'assessment.invokeFailed'
}
finally {
  $ErrorActionPreference = 'Stop'
  $restoreDriftRoot = if ($null -eq $previousDriftRoot) {
    [System.Management.Automation.Language.NullString]::Value
  } else {
    $previousDriftRoot
  }
  [Environment]::SetEnvironmentVariable('MAESTER_FOLDER_DRIFT', $restoreDriftRoot, 'Process')
}
if ($invocationErrors.Count -gt 0) { throw 'assessment.invocationErrors' }
$assessmentEvidence = Get-MaesterAssessmentEvidence -Output $maesterOutput -JunitPath $junitPath -TestsPath $testsPath -ReportPath $outputHtmlPath
Write-Output 'Maester assessment health verified; policy findings may remain.'
Write-Output 'Invoke-Maester execution completed.'
Write-Output 'Maester run completed. Report generated successfully.'

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
