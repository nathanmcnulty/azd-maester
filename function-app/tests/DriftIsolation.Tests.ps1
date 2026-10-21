#Requires -Version 7.6
BeforeAll {
    $script:runner = Get-Content (Join-Path $PSScriptRoot '../src/MaesterTimerTrigger/run.ps1') -Raw
    $start = $script:runner.IndexOf('Write-Step "Running Invoke-Maester')
    $end = $script:runner.IndexOf("Write-Step 'Invoke-Maester execution completed'", $start)
    if ($start -lt 0 -or $end -lt $start) { throw 'Production invocation block was not found.' }
    $script:invokeBlock = [scriptblock]::Create($script:runner.Substring($start, $end - $start))
    $script:originalDriftRoot = [Environment]::GetEnvironmentVariable('MAESTER_FOLDER_DRIFT', 'Process')
    $script:originalMarker = [Environment]::GetEnvironmentVariable('DRIFT_TEST_MARKER', 'Process')
    function Write-Step { param([string]$Message) }
    function Invoke-Maester {
        $script:observedDriftRoot = [Environment]::GetEnvironmentVariable('MAESTER_FOLDER_DRIFT', 'Process')
        if ($script:throwDuringRun) { throw 'controlled Maester failure' }
    }
}
Describe 'Default-disabled drift isolation' {
    AfterEach {
        [Environment]::SetEnvironmentVariable('MAESTER_FOLDER_DRIFT', $script:originalDriftRoot, 'Process')
        [Environment]::SetEnvironmentVariable('DRIFT_TEST_MARKER', $script:originalMarker, 'Process')
    }
    It 'isolates and restores an inherited root when failure is <fails>' -ForEach @(@{fails=$false}, @{fails=$true}) {
        $maesterInvokeParameters = @{}; $testsPath = 'fixture-tests'
        $script:throwDuringRun = $fails
        [Environment]::SetEnvironmentVariable('MAESTER_FOLDER_DRIFT', 'unapproved-inherited-folder', 'Process')
        if ($fails) { { & $script:invokeBlock } | Should -Throw '*controlled Maester failure*' }
        else { & $script:invokeBlock | Out-Null }
        $script:observedDriftRoot | Should -BeNullOrEmpty
        [Environment]::GetEnvironmentVariable('MAESTER_FOLDER_DRIFT', 'Process') | Should -BeExactly 'unapproved-inherited-folder'
    }
    It 'preserves an unset root after the run' {
        $maesterInvokeParameters = @{}; $testsPath = 'fixture-tests'; $script:throwDuringRun = $false
        [Environment]::SetEnvironmentVariable('MAESTER_FOLDER_DRIFT', $null, 'Process')
        & $script:invokeBlock | Out-Null
        $script:observedDriftRoot | Should -BeNullOrEmpty
        [Environment]::GetEnvironmentVariable('MAESTER_FOLDER_DRIFT', 'Process') | Should -BeNullOrEmpty
    }
    It 'excludes the upstream drift file before Pester discovery while ordinary tests run' {
        $testsPath = Join-Path $TestDrive 'suite'
        $drift = Join-Path $testsPath 'Maester/Drift'; $null = New-Item -ItemType Directory -Path $drift
        @'
Describe 'Ordinary assessment fixture' { It 'runs' { 1 | Should -Be 1 } }
'@ | Set-Content (Join-Path $testsPath 'Ordinary.Tests.ps1')
        @'
BeforeDiscovery {
    [IO.File]::WriteAllText($env:DRIFT_TEST_MARKER, 'unapproved discovery')
    throw 'Drift discovery must not run in the default assessment.'
}
Describe 'Drift' { It 'must not run' { $false | Should -BeTrue } }
'@ | Set-Content (Join-Path $drift 'MT1060Drift.tests.ps1')
        $configStart = $script:runner.IndexOf('$pesterConfig = [PesterConfiguration]@{')
        $configEnd = $script:runner.IndexOf('$maesterInvokeParameters =', $configStart)
        if ($configStart -lt 0 -or $configEnd -lt $configStart) { throw 'Production Pester configuration was not found.' }
        $configuration = $script:runner.Substring($configStart, $configEnd - $configStart)
        $harness = @'
param([string]$TestsPath)
$ErrorActionPreference = 'Stop'
Import-Module Pester -RequiredVersion 6.2.0 -Force
$junitPath = Join-Path $TestsPath 'fixture-junit.xml'
'@ + "`n" + $configuration + @'

$pesterConfig.Run.Path = $TestsPath
$pesterConfig.Run.PassThru = $true
$pesterConfig.Output.Verbosity = 'None'
$result = Invoke-Pester -Configuration $pesterConfig
if ($result.TotalCount -ne 1 -or $result.PassedCount -ne 1 -or $result.FailedContainers.Count -ne 0) { exit 1 }
'@
        $path = Join-Path $TestDrive 'discovery-harness.ps1'; $harness | Set-Content $path
        $env:DRIFT_TEST_MARKER = Join-Path $TestDrive 'discovery-marker'
        $exe = Join-Path $PSHOME $(if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' })
        $output = & $exe -NoProfile -File $path -TestsPath $testsPath 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
        Test-Path $env:DRIFT_TEST_MARKER | Should -BeFalse
    }
}
