Describe 'Legacy <Name> runner result boundary' -ForEach @(
  @{ Name = 'Automation'; RunnerPath = 'automation-account/scripts/Invoke-MaesterAutomationRunbook.ps1'; Invocation = 'Write-Output'; StrictAssessment = $true }
  @{ Name = 'Container Job'; RunnerPath = 'container-app-job/scripts/Invoke-MaesterContainerJob.ps1'; Invocation = 'Write-Output'; StrictAssessment = $true }
  @{ Name = 'Function App'; RunnerPath = 'function-app/src/MaesterTimerTrigger/run.ps1'; Invocation = 'Write-Step'; StrictAssessment = $true }
) {
  AfterAll {
    foreach ($name in 'RUNNER_TEST_TEMP_ROOT', 'RUNNER_TEST_MODE', 'RUNNER_TEST_STORAGE', 'RUNNER_TEST_FAIL_UPLOAD') {
      [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
  }
  BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $runnerPath = Join-Path $repoRoot $RunnerPath
    $source = Get-Content -LiteralPath $runnerPath -Raw
    $start = $source.IndexOf("$Invocation `"Running Invoke-Maester")
    $end = $source.IndexOf('# Publish to web app', $start)
    if ($start -lt 0 -or $end -le $start) { throw 'Could not isolate the production Maester run and report block.' }
    $runBlock = $source.Substring($start, $end - $start)
    $gateSetup = "Import-Module '__GATE__' -Force"
    if ($Name -eq 'Automation') {
      $gateStart = $source.IndexOf('# BEGIN shared pure assessment health contract')
      $gateEnd = $source.IndexOf('# END shared pure assessment health contract')
      if ($gateStart -lt 0 -or $gateEnd -le $gateStart) { throw 'Production assessment contract missing.' }
      $gateSetup = $source.Substring($gateStart, $gateEnd - $gateStart)
    }
    $harness = @'
$ErrorActionPreference = 'Continue'
Import-Module Pester -RequiredVersion 6.2.0 -Force
$maesterInvokeParameters = @{}
$strictAssessment = __STRICT__
if ($strictAssessment) {
__GATE_SETUP__
. '__FIXTURE__'
}
$tempRoot = $env:RUNNER_TEST_TEMP_ROOT
$testsPath = Join-Path $tempRoot 'tests'
$junitPath = Join-Path $tempRoot 'pester-junit.xml'
$StorageAccountName = $env:RUNNER_TEST_STORAGE
$ExportContainer = 'archive'
$DashboardContainer = 'latest'
function Write-Step { param([string] $Message) }
function Invoke-Maester {
  if ($env:RUNNER_TEST_MODE -eq 'throw') { throw 'simulated execution failure' }
  if ($env:RUNNER_TEST_MODE -in @('result','invalid-counts')) {
    $name = if ($strictAssessment) { 'assessment.html' } else { 'report.html' }
    Set-Content -LiteralPath (Join-Path $tempRoot $name) -Value '<html>security finding</html>'
    if ($strictAssessment) {
      Set-Content $junitPath '<testsuites tests="5" errors="0" failures="1" disabled="3" />'
      $result = New-TestAssessmentResult $testsPath
      if ($env:RUNNER_TEST_MODE -eq 'invalid-counts') { $result.TotalCount = 999 }
      $result | Add-Member OutputFiles ([pscustomobject]@{ OutputHtmlFile = (Join-Path $tempRoot 'assessment.html') })
      return $result
    }
  }
}
function Get-PlainToken { 'test-token' }
function Compress-GzipFile { param($InputPath, $OutputPath) }
function Set-BlobContent {
  param($AccountName, $Container, $BlobName, $SourcePath, $StorageToken, $ContentType, $AccessTier, $ContentEncoding)
  if ($BlobName -eq 'latest.html') {
    Set-Content -LiteralPath (Join-Path $tempRoot 'latest-attempted') -Value 'yes'
    if ($env:RUNNER_TEST_FAIL_UPLOAD -eq '1') { throw 'simulated upload failure' }
  }
}
'@.Replace('__GATE_SETUP__', $gateSetup).Replace('__STRICT__', ('$' + $StrictAssessment.ToString().ToLowerInvariant())).Replace('__GATE__', (Join-Path $repoRoot 'function-app/src/Maester.AssessmentEvidence.psm1').Replace("'", "''")).Replace('__FIXTURE__', (Join-Path $repoRoot 'function-app/tests/fixtures/AssessmentEvidence.ps1').Replace("'", "''")) + "`n" + $runBlock + "`nWrite-Output 'RUNNER_SUCCESS'`n"
    $harnessPath = Join-Path $TestDrive 'runner-harness.ps1'
    Set-Content -LiteralPath $harnessPath -Value $harness
  }

  It 'exits nonzero and never creates success HTML when Invoke-Maester throws' {
    $env:RUNNER_TEST_TEMP_ROOT = Join-Path $TestDrive 'throw'
    $env:RUNNER_TEST_MODE = 'throw'
    $env:RUNNER_TEST_STORAGE = ''
    $env:RUNNER_TEST_FAIL_UPLOAD = '0'
    New-Item -ItemType Directory -Path $env:RUNNER_TEST_TEMP_ROOT | Out-Null
    $output = & pwsh -NoProfile -File $harnessPath 2>&1
    $LASTEXITCODE | Should -Be 1
    @($output) -join "`n" | Should -Not -Match 'RUNNER_SUCCESS|Maester Run Completed'
    @(Get-ChildItem -LiteralPath $env:RUNNER_TEST_TEMP_ROOT -Filter '*.html').Count | Should -Be 0
  }

  It 'rejects malformed structured results before publishing an existing HTML report' {
    $env:RUNNER_TEST_TEMP_ROOT = Join-Path $TestDrive 'invalid-counts'
    $env:RUNNER_TEST_MODE = 'invalid-counts'
    $env:RUNNER_TEST_STORAGE = 'fixture'
    $env:RUNNER_TEST_FAIL_UPLOAD = '0'
    New-Item -ItemType Directory -Path $env:RUNNER_TEST_TEMP_ROOT | Out-Null
    $output = & pwsh -NoProfile -File $harnessPath 2>&1
    $LASTEXITCODE | Should -Be 1
    @($output) -join "`n" | Should -Match 'countMismatch'
    @($output) -join "`n" | Should -Not -Match 'RUNNER_SUCCESS'
    Test-Path -LiteralPath (Join-Path $env:RUNNER_TEST_TEMP_ROOT 'assessment.html') | Should -BeTrue
    Test-Path -LiteralPath (Join-Path $env:RUNNER_TEST_TEMP_ROOT 'latest-attempted') | Should -BeFalse
  }
  It 'exits nonzero when Maester produces no report' {
    $env:RUNNER_TEST_TEMP_ROOT = Join-Path $TestDrive 'missing'
    $env:RUNNER_TEST_MODE = 'missing'
    $env:RUNNER_TEST_STORAGE = ''
    $env:RUNNER_TEST_FAIL_UPLOAD = '0'
    New-Item -ItemType Directory -Path $env:RUNNER_TEST_TEMP_ROOT | Out-Null
    $output = & pwsh -NoProfile -File $harnessPath 2>&1
    $LASTEXITCODE | Should -Be 1
    @($output) -join "`n" | Should -Not -Match 'RUNNER_SUCCESS|Maester Run Completed'
    @(Get-ChildItem -LiteralPath $env:RUNNER_TEST_TEMP_ROOT -Filter '*.html').Count | Should -Be 0
  }

  It 'preserves genuine test findings as a successful runner result' {
    $env:RUNNER_TEST_TEMP_ROOT = Join-Path $TestDrive 'finding'
    $env:RUNNER_TEST_MODE = 'result'
    $env:RUNNER_TEST_STORAGE = ''
    $env:RUNNER_TEST_FAIL_UPLOAD = '0'
    New-Item -ItemType Directory -Path $env:RUNNER_TEST_TEMP_ROOT | Out-Null
    $output = & pwsh -NoProfile -File $harnessPath 2>&1
    $LASTEXITCODE | Should -Be 0
    @($output) -join "`n" | Should -Match 'RUNNER_SUCCESS'
    Get-Content -LiteralPath (Join-Path $env:RUNNER_TEST_TEMP_ROOT $(if ($StrictAssessment) { 'assessment.html' } else { 'report.html' })) -Raw | Should -Match 'security finding'
  }

  It 'exits nonzero when publishing the latest report fails' {
    $env:RUNNER_TEST_TEMP_ROOT = Join-Path $TestDrive 'upload'
    $env:RUNNER_TEST_MODE = 'result'
    $env:RUNNER_TEST_STORAGE = 'test-account'
    $env:RUNNER_TEST_FAIL_UPLOAD = '1'
    New-Item -ItemType Directory -Path $env:RUNNER_TEST_TEMP_ROOT | Out-Null
    $output = & pwsh -NoProfile -File $harnessPath 2>&1
    $LASTEXITCODE | Should -Be 1
    (Test-Path -LiteralPath (Join-Path $env:RUNNER_TEST_TEMP_ROOT 'latest-attempted')) | Should -BeTrue
    @($output) -join "`n" | Should -Not -Match 'RUNNER_SUCCESS'
  }
}
