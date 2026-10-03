Describe 'Locked Function module packaging' {
  AfterAll {
    foreach ($name in 'RUNNER_TEST_TEMP_ROOT', 'RUNNER_TEST_PLAN') {
      [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
  }
  BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $deployPath = Join-Path $repoRoot 'function-app/scripts/Deploy-FunctionCode.ps1'
    $installerPath = Join-Path $repoRoot 'function-app/scripts/Install-LockedModules.ps1'
    $harness = @'
$env:TEMP = $env:RUNNER_TEST_TEMP_ROOT
function Invoke-WebRequest {
  param($Uri, $OutFile)
  Set-Content -LiteralPath (Join-Path $env:TEMP 'download-attempted') -Value 'yes'
  Set-Content -LiteralPath $OutFile -Value 'untrusted bytes'
}
function az {
  Set-Content -LiteralPath (Join-Path $env:TEMP 'az-called') -Value 'yes'
  $global:LASTEXITCODE = 0
}
& '__DEPLOY_SCRIPT__' -SubscriptionId '11111111-1111-4111-8111-111111111111' `
  -ResourceGroupName 'rg-test' -FunctionAppName 'func-test' -Plan $env:RUNNER_TEST_PLAN
'@.Replace('__DEPLOY_SCRIPT__', $deployPath.Replace("'", "''"))
    $harnessPath = Join-Path $TestDrive 'package-harness.ps1'
    Set-Content -LiteralPath $harnessPath -Value $harness
  }

  It 'rejects tampered package bytes before zip deployment on <Plan>' -ForEach @(
    @{ Plan = 'FC1' }, @{ Plan = 'Y1' }, @{ Plan = 'B1' }
  ) {
      $env:RUNNER_TEST_TEMP_ROOT = Join-Path $TestDrive "tamper-$Plan"
      $env:RUNNER_TEST_PLAN = $Plan
      New-Item -ItemType Directory -Path $env:RUNNER_TEST_TEMP_ROOT | Out-Null
      $output = & pwsh -NoProfile -File $harnessPath 2>&1
      $LASTEXITCODE | Should -Be 1
      @($output) -join "`n" | Should -Match 'failed SHA-256 verification'
      (Test-Path -LiteralPath (Join-Path $env:RUNNER_TEST_TEMP_ROOT 'download-attempted')) | Should -BeTrue
      (Test-Path -LiteralPath (Join-Path $env:RUNNER_TEST_TEMP_ROOT 'az-called')) | Should -BeFalse
      @(Get-ChildItem -LiteralPath $env:RUNNER_TEST_TEMP_ROOT -Filter '*.zip').Count | Should -Be 0
  }

  It 'rejects a hash-valid package without the locked module manifest' {
    $packageDir = Join-Path $TestDrive 'empty-package'
    $destination = Join-Path $TestDrive 'empty-modules'
    New-Item -ItemType Directory -Path $packageDir | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $source = Join-Path $TestDrive 'zip-source'
    New-Item -ItemType Directory -Path $source | Out-Null
    Set-Content -LiteralPath (Join-Path $source 'other.txt') -Value 'no manifest'
    $packagePath = Join-Path $packageDir 'Fake.1.0.0.nupkg'
    [IO.Compression.ZipFile]::CreateFromDirectory($source, $packagePath)
    $hash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash
    $lockPath = Join-Path $TestDrive 'empty.lock.json'
    @{ schemaVersion = 1; packages = @(@{ name = 'Fake'; version = '1.0.0'; sha256 = $hash }) } |
      ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $lockPath
    { & $installerPath -LockPath $lockPath -PackageDirectory $packageDir -DestinationRoot $destination } |
      Should -Throw '*has no expected module manifest*'
  }
}
