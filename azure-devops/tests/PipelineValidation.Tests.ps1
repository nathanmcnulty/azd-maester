BeforeAll {
  Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/PipelineValidation.Core.psm1') -Force
  function global:Invoke-ADOPSRestMethod {
    param([string]$Method, [string]$Uri)
    if ($Uri -match '/timeline\?') { return [pscustomobject]@{ records = $script:records } }
    if ($Uri -match '/artifacts\?') { return [pscustomobject]@{ value = $script:artifacts } }
    if ($Uri -eq 'https://logs/runner') { return $script:runnerLog }
    if ($Uri -eq 'https://logs/tests') { return $script:testLog }
    throw "Unexpected test URI: $Uri"
  }
  function New-TimelineTask($name, $result, $logUrl) {
    [pscustomobject]@{ type = 'Task'; name = $name; state = 'completed'; result = $result; log = [pscustomobject]@{ url = $logUrl } }
  }
}

Describe 'Failed Maester pipeline classification' {
  BeforeEach {
    $script:records = @(
      ([pscustomobject]@{ type = 'Job'; name = 'MaesterRun'; state = 'completed'; result = 'failed' }),
      (New-TimelineTask 'Checkout' 'succeeded' ''),
      (New-TimelineTask 'Run Maester' 'failed' 'https://logs/runner'),
      (New-TimelineTask 'Publish Maester Html Report' 'succeeded' ''),
      (New-TimelineTask 'Publish Pester Test Results' 'succeeded' 'https://logs/tests')
    )
    $script:artifacts = @([pscustomobject]@{ name = 'TestResults' })
    $script:runnerLog = 'AZD_MAESTER_RESULT=FINDINGS;FAILED=3'
    $script:testLog = 'There are one or more test failures detected in result files'
  }

  It 'accepts a completed run whose sole task failures are recorded test findings' {
    $script:runnerLog = '2026-10-03 11:00:00 AZD_MAESTER_RESULT=FINDINGS;FAILED=3'
    Test-ExpectedMaesterFinding -Organization org -Project project -RunId 42 | Should -BeTrue
  }

  It 'rejects a report publication failure even when the Maester log has findings' {
    $script:records[3].result = 'failed'
    Test-ExpectedMaesterFinding -Organization org -Project project -RunId 42 | Should -BeFalse
  }

  It 'rejects a second unrelated failed task' {
    $script:records += New-TimelineTask 'Upload output' 'failed' ''
    Test-ExpectedMaesterFinding -Organization org -Project project -RunId 42 | Should -BeFalse
  }

  It 'rejects an unrelated NUnit publisher failure' {
    $script:records[4].result = 'failed'
    Test-ExpectedMaesterFinding -Organization org -Project project -RunId 42 | Should -BeFalse
  }

  It 'rejects an additional failed job with no task record' {
    $script:records += [pscustomobject]@{ type = 'Job'; name = 'OtherJob'; state = 'completed'; result = 'failed' }
    Test-ExpectedMaesterFinding -Organization org -Project project -RunId 42 | Should -BeFalse
  }

  It 'rejects a missing artifact or missing runner finding marker' {
    $script:artifacts = @()
    Test-ExpectedMaesterFinding -Organization org -Project project -RunId 42 | Should -BeFalse
    $script:artifacts = @([pscustomobject]@{ name = 'TestResults' })
    $script:runnerLog = 'AzurePowerShell failed to import a module'
    Test-ExpectedMaesterFinding -Organization org -Project project -RunId 42 | Should -BeFalse
  }

  It 'rejects incomplete, ambiguous, and skipped task timelines' {
    $script:records[2].state = 'inProgress'
    Test-ExpectedMaesterFinding -Organization org -Project project -RunId 42 | Should -BeFalse
    $script:records[2].state = 'completed'
    $script:records += New-TimelineTask 'Run Maester' 'succeeded' ''
    Test-ExpectedMaesterFinding -Organization org -Project project -RunId 42 | Should -BeFalse
    $script:records = @($script:records | Select-Object -First 5)
    $script:records[1].result = 'skipped'
    Test-ExpectedMaesterFinding -Organization org -Project project -RunId 42 | Should -BeFalse
  }
}

AfterAll { Remove-Item Function:\Invoke-ADOPSRestMethod -ErrorAction SilentlyContinue }

Describe 'Maester NUnit result boundary' {
  BeforeAll {
    $runnerPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/Invoke-MaesterAzureDevOpsRun.ps1'
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($runnerPath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw 'Runner script failed PowerShell parsing.' }
    $functionAst = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-NUnitFailureCount' }, $true)
    if (-not $functionAst) { throw 'Runner NUnit helper was not found.' }
    . ([scriptblock]::Create($functionAst.Extent.Text))
  }

  It 'fails when Maester produced no NUnit file' {
    { Get-NUnitFailureCount -Path (Join-Path $TestDrive 'absent.xml') } | Should -Throw '*was not generated*'
  }

  It 'fails on malformed or unrecognized NUnit data' {
    $path = Join-Path $TestDrive 'unknown.xml'
    Set-Content -LiteralPath $path -Value '<unknown />'
    { Get-NUnitFailureCount -Path $path } | Should -Throw '*no recognized failure count*'
  }

  It 'reads a genuine zero-finding NUnit result' {
    $path = Join-Path $TestDrive 'result.xml'
    Set-Content -LiteralPath $path -Value '<test-results failures="0" />'
    Get-NUnitFailureCount -Path $path | Should -Be 0
  }
}
