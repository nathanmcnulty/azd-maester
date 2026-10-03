Describe 'FC1 required module packaging' {
  AfterAll {
    foreach ($name in 'RUNNER_TEST_TEMP_ROOT', 'RUNNER_TEST_MODE') {
      [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
  }
  BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $deployPath = Join-Path $repoRoot 'function-app/scripts/Deploy-FunctionCode.ps1'
    $harness = @'
$env:TEMP = $env:RUNNER_TEST_TEMP_ROOT
function Save-Module {
  Set-Content -LiteralPath (Join-Path $env:TEMP 'save-attempted') -Value 'yes'
  if ($env:RUNNER_TEST_MODE -eq 'throw') { throw 'simulated package download failure' }
}
function az {
  Set-Content -LiteralPath (Join-Path $env:TEMP 'az-called') -Value 'yes'
  $global:LASTEXITCODE = 0
}
& '__DEPLOY_SCRIPT__' -SubscriptionId '11111111-1111-4111-8111-111111111111' `
  -ResourceGroupName 'rg-test' -FunctionAppName 'func-test' -Plan FC1
'@.Replace('__DEPLOY_SCRIPT__', $deployPath.Replace("'", "''"))
    $harnessPath = Join-Path $TestDrive 'package-harness.ps1'
    Set-Content -LiteralPath $harnessPath -Value $harness
  }

  It 'stops before zip deployment when Save-Module throws' {
    $env:RUNNER_TEST_TEMP_ROOT = Join-Path $TestDrive 'download-failure'
    $env:RUNNER_TEST_MODE = 'throw'
    New-Item -ItemType Directory -Path $env:RUNNER_TEST_TEMP_ROOT | Out-Null
    $output = & pwsh -NoProfile -File $harnessPath 2>&1
    $LASTEXITCODE | Should -Be 1
    @($output) -join "`n" | Should -Match 'Failed to bundle required module'
    (Test-Path -LiteralPath (Join-Path $env:RUNNER_TEST_TEMP_ROOT 'save-attempted')) | Should -BeTrue
    (Test-Path -LiteralPath (Join-Path $env:RUNNER_TEST_TEMP_ROOT 'az-called')) | Should -BeFalse
    @(Get-ChildItem -LiteralPath $env:RUNNER_TEST_TEMP_ROOT -Filter '*.zip').Count | Should -Be 0
  }

  It 'rejects a nominal Save-Module return without a module manifest' {
    $env:RUNNER_TEST_TEMP_ROOT = Join-Path $TestDrive 'missing-manifest'
    $env:RUNNER_TEST_MODE = 'empty'
    New-Item -ItemType Directory -Path $env:RUNNER_TEST_TEMP_ROOT | Out-Null
    $output = & pwsh -NoProfile -File $harnessPath 2>&1
    $LASTEXITCODE | Should -Be 1
    @($output) -join "`n" | Should -Match 'was not saved with a module'
    (Test-Path -LiteralPath (Join-Path $env:RUNNER_TEST_TEMP_ROOT 'az-called')) | Should -BeFalse
    @(Get-ChildItem -LiteralPath $env:RUNNER_TEST_TEMP_ROOT -Filter '*.zip').Count | Should -Be 0
  }
}
