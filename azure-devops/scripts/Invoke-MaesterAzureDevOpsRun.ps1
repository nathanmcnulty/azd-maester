[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$IncludeExchange = 'false',

  [Parameter(Mandatory = $false)]
  [string]$IncludeTeams = 'false',

  [Parameter(Mandatory = $false)]
  [string]$IncludeAzure = 'false',

  [Parameter(Mandatory = $false)]
  [string]$IncludeWebApp = 'false',

  [Parameter(Mandatory = $false)]
  [string]$StorageAccountName,

  [Parameter(Mandatory = $false)]
  [string]$WebAppName,

  [Parameter(Mandatory = $false)]
  [string]$WebAppResourceGroup,

  [Parameter(Mandatory = $false)]
  [string]$TenantId,

  [Parameter(Mandatory = $false)]
  [string]$ClientId,

  [Parameter(Mandatory = $false)]
  [string]$MailRecipient = '',

  [Parameter(Mandatory = $false)]
  [string]$FailOnTestFailures = 'true'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-Bool {
  param([Parameter(Mandatory = $true)][string]$Value)

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return $false
  }

  return $Value.Trim().ToLower() -eq 'true'
}

function ConvertTo-PlainTextToken {
  param([Parameter(Mandatory = $true)]$TokenValue)

  if ($TokenValue -is [string]) {
    return $TokenValue
  }

  if ($TokenValue -is [System.Security.SecureString]) {
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($TokenValue)
    try {
      return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
      [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
  }

  return [string]$TokenValue
}

function Get-AzAccessTokenPlainText {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceUrl,

    [Parameter(Mandatory = $false)]
    [string]$Tenant
  )

  $tokenParams = @{
    ResourceUrl = $ResourceUrl
  }

  if (-not [string]::IsNullOrWhiteSpace($Tenant)) {
    $tokenParams['TenantId'] = $Tenant
  }

  $tokenResponse = Get-AzAccessToken @tokenParams -AsSecureString
  return (ConvertTo-PlainTextToken -TokenValue $tokenResponse.Token).Trim()
}

function Get-JwtTokenSummary {
  param([Parameter(Mandatory = $true)][string]$Token)

  $tokenText = [string]$Token
  $tokenText = $tokenText.Trim()

  $dotCount = ([regex]::Matches($tokenText, '\.')).Count
  if ($dotCount -lt 2) {
    return [pscustomobject]@{
      AppId  = ''
      Tid    = ''
      Aud    = ''
      IdType = ''
      HasScp = $false
      IsJwt  = $false
      Length = $tokenText.Length
      DotCount = $dotCount
    }
  }

  try {
    Add-Type -AssemblyName System.IdentityModel.Tokens.Jwt -ErrorAction SilentlyContinue
    $tokenHandler = [System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]::new()
    $jwt = $tokenHandler.ReadJwtToken($tokenText)
    $claimMap = @{}
    foreach ($claim in $jwt.Claims) {
      if (-not $claimMap.ContainsKey($claim.Type)) {
        $claimMap[$claim.Type] = $claim.Value
      }
    }

    $appidClaim = ''
    if ($claimMap.ContainsKey('appid')) {
      $appidClaim = [string]$claimMap['appid']
    }

    $tidClaim = ''
    if ($claimMap.ContainsKey('tid')) {
      $tidClaim = [string]$claimMap['tid']
    }

    $idtypClaim = ''
    if ($claimMap.ContainsKey('idtyp')) {
      $idtypClaim = [string]$claimMap['idtyp']
    }

    $hasScpClaim = $claimMap.ContainsKey('scp') -and -not [string]::IsNullOrWhiteSpace([string]$claimMap['scp'])

    return [pscustomobject]@{
      AppId  = $appidClaim
      Tid    = $tidClaim
      Aud    = [string]$jwt.Audiences -join ','
      IdType = $idtypClaim
      HasScp = $hasScpClaim
      IsJwt  = $true
      Length = $tokenText.Length
      DotCount = $dotCount
    }
  }
  catch {
    return [pscustomobject]@{
      AppId  = ''
      Tid    = ''
      Aud    = ''
      IdType = ''
      HasScp = $false
      IsJwt  = $false
      Length = $tokenText.Length
      DotCount = $dotCount
    }
  }
}

function Install-RequiredModule {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $false)]
    [string]$RequiredVersion
  )

  $installParams = @{
    Name         = $Name
    Scope        = 'CurrentUser'
    Force        = $true
    AllowClobber = $true
  }

  if (-not [string]::IsNullOrWhiteSpace($RequiredVersion)) {
    $installParams['RequiredVersion'] = $RequiredVersion
  }

  Install-Module @installParams
}

function Compress-FileToGzip {
  param(
    [Parameter(Mandatory = $true)]
    [string]$InputFilePath,

    [Parameter(Mandatory = $true)]
    [string]$OutputFilePath
  )

  $inputBytes = [System.IO.File]::ReadAllBytes($InputFilePath)
  $outputDirectory = Split-Path -Path $OutputFilePath -Parent
  if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
  }

  $outStream = [System.IO.File]::Open($OutputFilePath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
  try {
    $gzipStream = New-Object System.IO.Compression.GzipStream($outStream, [System.IO.Compression.CompressionMode]::Compress)
    try {
      $gzipStream.Write($inputBytes, 0, $inputBytes.Length)
    }
    finally {
      $gzipStream.Dispose()
    }
  }
  finally {
    $outStream.Dispose()
  }
}

function Get-NUnitFailureCount {
  param([Parameter(Mandatory = $true)][string]$Path)

  if (-not (Test-Path -Path $Path)) {
    return 0
  }

  [xml]$xml = Get-Content -Path $Path -Raw
  if ($xml.'test-results' -and $xml.'test-results'.failures) {
    return [int]$xml.'test-results'.failures
  }

  if ($xml.testRun -and $xml.testRun.ResultSummary -and $xml.testRun.ResultSummary.Counters -and $xml.testRun.ResultSummary.Counters.failed) {
    return [int]$xml.testRun.ResultSummary.Counters.failed
  }

  return 0
}

$includeExchangeBool = ConvertTo-Bool -Value $IncludeExchange
$includeTeamsBool = ConvertTo-Bool -Value $IncludeTeams
$includeWebAppBool = ConvertTo-Bool -Value $IncludeWebApp
$failOnTestFailuresBool = ConvertTo-Bool -Value $FailOnTestFailures

Write-Host 'Installing required PowerShell modules...'
$exchangeOnlineModuleVersion = '3.9.2'
$teamsModuleVersion = '6.9.0'

Install-RequiredModule -Name 'Maester'
Install-RequiredModule -Name 'Pester'
Install-RequiredModule -Name 'NuGet'
Install-RequiredModule -Name 'PackageManagement'
Install-RequiredModule -Name 'Microsoft.Graph.Authentication'
Install-RequiredModule -Name 'Az.Accounts'
Install-RequiredModule -Name 'Az.Storage'

if ($includeExchangeBool) {
  Install-RequiredModule -Name 'ExchangeOnlineManagement' -RequiredVersion $exchangeOnlineModuleVersion
}

if ($includeTeamsBool) {
  Install-RequiredModule -Name 'MicrosoftTeams' -RequiredVersion $teamsModuleVersion
}

Import-Module Az.Accounts -Force
Import-Module Az.Storage -Force
if ($includeExchangeBool) {
  Import-Module ExchangeOnlineManagement -RequiredVersion $exchangeOnlineModuleVersion -Force
}
if ($includeTeamsBool) {
  Import-Module MicrosoftTeams -RequiredVersion $teamsModuleVersion -Force
}
Import-Module Microsoft.Graph.Authentication -Force
Import-Module Maester -Force
if ($includeWebAppBool) {
  Import-Module Az.Websites -ErrorAction SilentlyContinue
}

Write-Host 'Acquiring Microsoft Graph token and connecting...'
$graphAccessToken = Get-AzAccessTokenPlainText -ResourceUrl 'https://graph.microsoft.com' -Tenant $TenantId
$graphSecureToken = ConvertTo-SecureString -String $graphAccessToken -AsPlainText -Force
Connect-MgGraph -AccessToken $graphSecureToken -NoWelcome

if ($includeExchangeBool) {
  Write-Host 'Connecting to Exchange Online with workload identity token...'
  $outlookToken = Get-AzAccessTokenPlainText -ResourceUrl 'https://outlook.office365.com' -Tenant $TenantId

  $exoOrganization = $null
  try {
    $domainsResponse = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/domains?$select=id,isInitial'
    if ($domainsResponse -and $domainsResponse.value) {
      $initialDomain = @($domainsResponse.value | Where-Object { $_.isInitial -eq $true }) | Select-Object -First 1
      if ($initialDomain -and $initialDomain.id) {
        $exoOrganization = $initialDomain.id
      }
    }
  }
  catch {
    Write-Warning ("Could not resolve tenant initial domain for Exchange. Error: {0}" -f $_.Exception.Message)
  }

  $exoBaseArgs = @{
    AccessToken = $outlookToken
    ShowBanner  = $false
  }
  if (-not [string]::IsNullOrWhiteSpace($ClientId)) {
    $exoBaseArgs['AppId'] = $ClientId
  }

  $exoConnected = $false
  $exoMaxAttempts = 3
  $exoRetryDelay = 20
  for ($exoAttempt = 1; $exoAttempt -le $exoMaxAttempts; $exoAttempt++) {
    try {
      $connectedThisAttempt = $false

      if ($exoOrganization) {
        try {
          $argsWithOrg = @{} + $exoBaseArgs
          $argsWithOrg['Organization'] = $exoOrganization
          Connect-ExchangeOnline @argsWithOrg | Out-Null
          $connectedThisAttempt = $true
        }
        catch {
          Write-Verbose ("Exchange connection with Organization '{0}' failed. Retrying without Organization. Error: {1}" -f $exoOrganization, $_.Exception.Message)
        }
      }

      if (-not $connectedThisAttempt) {
        Connect-ExchangeOnline @exoBaseArgs | Out-Null
        $connectedThisAttempt = $true
      }

      if ($connectedThisAttempt) {
        $exoConnected = $true
        Write-Host 'Exchange Online connection established.'
        break
      }
    }
    catch {
      if ($exoAttempt -lt $exoMaxAttempts) {
        Write-Warning ("Exchange Online connection attempt {0}/{1} failed: {2}. Retrying in {3}s..." -f $exoAttempt, $exoMaxAttempts, $_.Exception.Message, $exoRetryDelay)
        Start-Sleep -Seconds $exoRetryDelay
        $exoRetryDelay = [Math]::Min($exoRetryDelay * 2, 120)
      }
      else {
        Write-Warning ("Exchange Online connection failed after {0} attempts. Exchange-related tests may be skipped. Last error: {1}" -f $exoMaxAttempts, $_.Exception.Message)
      }
    }
  }

  if ($exoConnected) {
    try {
      $ippsConnectArgs = @{
        AccessToken = $outlookToken
        ShowBanner  = $false
      }
      if (-not [string]::IsNullOrWhiteSpace($ClientId)) {
        $ippsConnectArgs['AppId'] = $ClientId
      }
      if ($exoOrganization) {
        $ippsConnectArgs['Organization'] = $exoOrganization
      }
      Connect-IPPSSession @ippsConnectArgs | Out-Null

      Write-Host 'Security & Compliance (IPPS) connection established.'
    }
    catch {
      Write-Warning ("Security & Compliance (IPPS) connection failed. Compliance-related tests may be skipped. Error: {0}" -f $_.Exception.Message)
    }
  }
}

if ($includeTeamsBool) {
  Write-Host 'Connecting to Microsoft Teams with workload identity tokens...'
  try {
    $teamsToken = Get-AzAccessTokenPlainText -ResourceUrl '48ac35b8-9aa8-4d74-927d-1f4a14a0b239' -Tenant $TenantId

    $graphTokenSummary = Get-JwtTokenSummary -Token $graphAccessToken
    $teamsTokenSummary = Get-JwtTokenSummary -Token $teamsToken
    Write-Host ("Teams token summary: Graph(idtyp={0}, appid={1}, aud={2}); Teams(idtyp={3}, appid={4}, aud={5})" -f $graphTokenSummary.IdType, $graphTokenSummary.AppId, $graphTokenSummary.Aud, $teamsTokenSummary.IdType, $teamsTokenSummary.AppId, $teamsTokenSummary.Aud)
    Write-Host ("Teams token format: GraphIsJwt={0}, TeamsIsJwt={1}, GraphLength={2}, TeamsLength={3}, GraphDots={4}, TeamsDots={5}" -f $graphTokenSummary.IsJwt, $teamsTokenSummary.IsJwt, $graphTokenSummary.Length, $teamsTokenSummary.Length, $graphTokenSummary.DotCount, $teamsTokenSummary.DotCount)

    if (-not [string]::IsNullOrWhiteSpace($ClientId)) {
      if (-not [string]::IsNullOrWhiteSpace($graphTokenSummary.AppId) -and $graphTokenSummary.AppId -ne $ClientId) {
        Write-Warning ("Graph access token appid '{0}' does not match expected workload identity client id '{1}'." -f $graphTokenSummary.AppId, $ClientId)
      }
      if (-not [string]::IsNullOrWhiteSpace($teamsTokenSummary.AppId) -and $teamsTokenSummary.AppId -ne $ClientId) {
        Write-Warning ("Teams access token appid '{0}' does not match expected workload identity client id '{1}'." -f $teamsTokenSummary.AppId, $ClientId)
      }
    }

    $tokenAttempts = @(
      [pscustomobject]@{
        Name   = 'graph-resource-url'
        Tokens = @($graphAccessToken, $teamsToken)
      }
    )

    $legacyGraphToken = $null
    try {
      $legacyGraphToken = ConvertTo-PlainTextToken -TokenValue (Get-AzAccessToken -ResourceTypeName MSGraph).Token
      if (-not [string]::IsNullOrWhiteSpace($legacyGraphToken) -and $legacyGraphToken -ne $graphAccessToken) {
        $tokenAttempts += [pscustomobject]@{
          Name   = 'graph-resource-type'
          Tokens = @($legacyGraphToken, $teamsToken)
        }
      }
    }
    catch {
      Write-Verbose ("Could not acquire fallback Graph token via ResourceTypeName. Error: {0}" -f $_.Exception.Message)
    }

    $teamsConnected = $false
    $teamsConnectionModes = @(
      [pscustomobject]@{
        Name = 'without-tenant'
        UseTenant = $false
      },
      [pscustomobject]@{
        Name = 'with-tenant'
        UseTenant = $true
      }
    )

    foreach ($attempt in $tokenAttempts) {
      foreach ($mode in $teamsConnectionModes) {
        if ($mode.UseTenant -and [string]::IsNullOrWhiteSpace($TenantId)) {
          continue
        }

        try {
          if ($mode.UseTenant) {
            Connect-MicrosoftTeams -AccessTokens $attempt.Tokens -TenantId $TenantId | Out-Null
          }
          else {
            Connect-MicrosoftTeams -AccessTokens $attempt.Tokens | Out-Null
          }
          $teamsConnected = $true
          Write-Host ("Microsoft Teams connection established (token mode: {0}, auth mode: {1})." -f $attempt.Name, $mode.Name)
          break
        }
        catch {
          Write-Warning ("Microsoft Teams connection attempt '{0}/{1}' failed: {2}" -f $attempt.Name, $mode.Name, $_.Exception.Message)
        }
      }

      if ($teamsConnected) {
        break
      }
    }

    if (-not $teamsConnected) {
      Write-Warning 'Microsoft Teams connection failed. Teams-related tests may be skipped. Non-interactive app auth requires a supported Teams directory role (for example Teams Administrator or Teams Communications Administrator).'
    }
  }
  catch {
    Write-Warning ("Microsoft Teams connection failed. Teams-related tests may be skipped. Error: {0}" -f $_.Exception.Message)
  }
}

$workingDirectory = Get-Location
$outputFolder = Join-Path -Path $workingDirectory -ChildPath 'test-results'
if (-not (Test-Path -Path $outputFolder)) {
  New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$testsRoot = Join-Path -Path $workingDirectory -ChildPath 'tests'
if (-not (Test-Path -Path $testsRoot)) {
  New-Item -Path $testsRoot -ItemType Directory -Force | Out-Null
}

Write-Host 'Downloading latest Maester tests...'
Install-MaesterTests $testsRoot

$resultsXmlPath = Join-Path -Path $outputFolder -ChildPath 'test-results.xml'
$latestHtmlPath = Join-Path -Path $outputFolder -ChildPath 'latest.html'

$pesterConfiguration = New-PesterConfiguration
$pesterConfiguration.TestResult.Enabled = $true
$pesterConfiguration.TestResult.OutputPath = $resultsXmlPath

Write-Host 'Running Maester tests...'
# Pipelines must stay non-interactive; never allow device-code/browser auth prompts.
Invoke-Maester -Path $testsRoot -PesterConfiguration $pesterConfiguration -OutputFolder $outputFolder -OutputHtmlFile $latestHtmlPath -NonInteractive:$true


if (-not (Test-Path -Path $latestHtmlPath)) {
  $fallbackHtml = Get-ChildItem -Path $outputFolder -Filter '*.html' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($fallbackHtml) {
    Copy-Item -Path $fallbackHtml.FullName -Destination $latestHtmlPath -Force
    Write-Warning "Maester did not create expected latest.html. Using '$($fallbackHtml.Name)' as latest.html."
  }
  else {
    throw "No Maester HTML report file was generated in '$outputFolder'."
  }
}

$timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$archiveGzipPath = Join-Path -Path $outputFolder -ChildPath "maester-report-$timestamp.html.gz"
Compress-FileToGzip -InputFilePath $latestHtmlPath -OutputFilePath $archiveGzipPath

if (-not [string]::IsNullOrWhiteSpace($StorageAccountName)) {
  Write-Host "Uploading reports to storage account '$StorageAccountName'..."
  $storageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount

  Set-AzStorageBlobContent -File $latestHtmlPath -Container 'latest' -Blob 'latest.html' -Context $storageContext -Force | Out-Null
  Set-AzStorageBlobContent -File $archiveGzipPath -Container 'archive' -Blob (Split-Path -Path $archiveGzipPath -Leaf) -Context $storageContext -Force | Out-Null
}
else {
  Write-Warning 'StorageAccountName was not provided. Skipping report upload to Azure Storage.'
}

if ($includeWebAppBool -and -not [string]::IsNullOrWhiteSpace($WebAppName) -and -not [string]::IsNullOrWhiteSpace($WebAppResourceGroup)) {
  Write-Host "Publishing latest report to Web App '$WebAppName'..."
  $webPackageDir = Join-Path -Path $outputFolder -ChildPath 'webapp-package'
  if (Test-Path -Path $webPackageDir) {
    Remove-Item -Path $webPackageDir -Recurse -Force
  }
  New-Item -Path $webPackageDir -ItemType Directory -Force | Out-Null

  Copy-Item -Path $latestHtmlPath -Destination (Join-Path -Path $webPackageDir -ChildPath 'index.html') -Force

  $zipPath = Join-Path -Path $outputFolder -ChildPath 'webapp-latest.zip'
  if (Test-Path -Path $zipPath) {
    Remove-Item -Path $zipPath -Force
  }
  Compress-Archive -Path (Join-Path -Path $webPackageDir -ChildPath '*') -DestinationPath $zipPath -Force

  Publish-AzWebApp -ResourceGroupName $WebAppResourceGroup -Name $WebAppName -ArchivePath $zipPath -Force | Out-Null
}
elseif ($includeWebAppBool) {
  Write-Warning 'IncludeWebApp=true but WebAppName/WebAppResourceGroup was not provided. Skipping web app publish.'
}

$failureCount = Get-NUnitFailureCount -Path $resultsXmlPath
if ($failureCount -gt 0) {
  $failureMessage = "$failureCount Maester test(s) failed."
  if ($failOnTestFailuresBool) {
    throw $failureMessage
  }

  Write-Warning "$failureMessage Continuing because FailOnTestFailures=false."
}

Write-Host 'Maester pipeline run completed successfully.'
Write-Host "Results XML: $resultsXmlPath"
Write-Host "Latest HTML: $latestHtmlPath"
Write-Host "Archive gzip: $archiveGzipPath"
