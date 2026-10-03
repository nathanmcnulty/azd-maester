Describe 'Legacy <Name> Web App report publication' -ForEach @(
  @{ Name = 'Automation'; RunnerPath = 'automation-account/scripts/Invoke-MaesterAutomationRunbook.ps1' }
  @{ Name = 'Container Job'; RunnerPath = 'container-app-job/scripts/Invoke-MaesterContainerJob.ps1' }
  @{ Name = 'Function App'; RunnerPath = 'function-app/src/MaesterTimerTrigger/run.ps1' }
) {
  AfterAll {
    foreach ($name in 'RUNNER_TEST_WEBAPP_MARKER', 'RUNNER_TEST_WEBAPP_FAIL', 'RUNNER_TEST_WEBAPP_SOURCE') {
      [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
  }
  BeforeAll {
    $runnerPath = Join-Path (Split-Path $PSScriptRoot -Parent) $RunnerPath
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($runnerPath, [ref]$tokens, [ref]$errors)
    if ($errors) { throw 'Runner source did not parse.' }
    $webHelper = $ast.Find({
      param($node)
      $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -eq 'Publish-WebAppContent'
    }, $true)
    if (-not $webHelper) { throw 'Production Web App helper was not found.' }
    $harness = @'
$ErrorActionPreference = 'Continue'
function Get-PlainToken { 'test-token' }
function Invoke-RestMethod {
  [CmdletBinding()]
  param($Method, $Uri, $Headers, $InFile, $ContentType)
  Set-Content -LiteralPath $env:RUNNER_TEST_WEBAPP_MARKER -Value 'attempted'
  if ($env:RUNNER_TEST_WEBAPP_FAIL -eq '1') {
    Write-Error 'simulated nonterminating Kudu failure'
  }
}
'@ + "`n" + $webHelper.Extent.Text + @'

Publish-WebAppContent -AppName 'test-webapp' -AppResourceGroupName 'test-rg' -SourcePath $env:RUNNER_TEST_WEBAPP_SOURCE
Write-Output 'WEBAPP_RUNNER_SUCCESS'
'@
    $harnessPath = Join-Path $TestDrive 'webapp-harness.ps1'
    Set-Content -LiteralPath $harnessPath -Value $harness
    $sourcePath = Join-Path $TestDrive 'report.html'
    Set-Content -LiteralPath $sourcePath -Value '<html>security finding</html>'
    $env:RUNNER_TEST_WEBAPP_SOURCE = $sourcePath
    $env:RUNNER_TEST_WEBAPP_MARKER = Join-Path $TestDrive 'webapp-attempted'
  }

  It 'turns a nonterminating Kudu error into runner failure without false publication success' {
    $env:RUNNER_TEST_WEBAPP_FAIL = '1'
    $output = & pwsh -NoProfile -File $harnessPath 2>&1
    $LASTEXITCODE | Should -Be 1
    Test-Path -LiteralPath $env:RUNNER_TEST_WEBAPP_MARKER | Should -BeTrue
    @($output) -join "`n" | Should -Not -Match 'Published latest report|WEBAPP_RUNNER_SUCCESS'
  }

  It 'reports publication success only after the HTTP call succeeds' {
    $env:RUNNER_TEST_WEBAPP_FAIL = '0'
    $output = & pwsh -NoProfile -File $harnessPath 2>&1
    $LASTEXITCODE | Should -Be 0
    @($output) -join "`n" | Should -Match 'Published latest report'
    @($output) -join "`n" | Should -Match 'WEBAPP_RUNNER_SUCCESS'
  }
}
