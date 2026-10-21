BeforeAll {
  $root = Split-Path $PSScriptRoot -Parent
  $text = Get-Content (Join-Path $root 'scripts/Invoke-MaesterAutomationRunbook.ps1') -Raw
  $start = $text.IndexOf('# BEGIN shared pure assessment health contract')
  $end = $text.IndexOf('# END shared pure assessment health contract')
  . ([scriptblock]::Create($text.Substring($start, $end - $start)))
  . (Join-Path $PSScriptRoot 'fixtures/AssessmentEvidence.ps1')
}
Describe 'Maester assessment integrity independently of compliance' {
  BeforeEach {
    $testsPath = Join-Path $TestDrive 'tests'
    $report = Join-Path $TestDrive 'assessment.html'
    $junit = Join-Path $TestDrive 'pester-junit.xml'
    Set-Content $report '<html>private policy findings</html>'
    Set-Content $junit '<testsuites tests="5" errors="0" failures="1" disabled="3" />'
    $result = New-TestAssessmentResult $testsPath
    $result | Add-Member OutputFiles ([pscustomobject]@{ OutputHtmlFile = $report })
  }
  It 'accepts only the reviewed Maester 2.3.0 result contract' {
    $result.CurrentVersion = [version]'2.3.0'
    (Get-MaesterAssessmentEvidence -Output $result -JunitPath $junit -TestsPath $testsPath -ReportPath $report).Outcome | Should -Be 'Completed'
  }
  It 'rejects stale and unreviewed Maester versions <_>' -ForEach @('2.2.0','2.3.1','3.0.0','2.3.0-preview') {
    $result.CurrentVersion = $_
    { Get-MaesterAssessmentEvidence -Output $result -JunitPath $junit -TestsPath $testsPath -ReportPath $report } | Should -Throw '*resultInvalid*'
  }
  It 'accepts genuine policy failures with expected skipped and excluded tests' {
    $e = Get-MaesterAssessmentEvidence -Output @('incidental output', $result) -JunitPath $junit -TestsPath $testsPath -ReportPath $report
    $e.Outcome | Should -Be 'Completed'
    $e.Counts.FailedCount | Should -Be 1
    $e.Counts.NotRunCount | Should -Be 2
    $e.ReportSha256 | Should -Be ((Get-FileHash $report).Hash.ToLowerInvariant())
    ($e | ConvertTo-Json -Depth 5) | Should -Not -Match 'private policy|ScriptBlock|tenant|token'
  }
  It 'rejects double-accounting the same Investigate row in JUnit' {
    $result.Tests[2].Result = 'Investigate'; $result.SkippedCount = 0; $result.InvestigateCount = 1
    Set-Content $junit '<testsuites tests="5" errors="0" failures="2" disabled="3" />'
    { Get-MaesterAssessmentEvidence -Output $result -JunitPath $junit -TestsPath $testsPath -ReportPath $report } | Should -Throw '*junitCountMismatch*'
  }
  It 'rejects an unrelated declared HTML report' {
    $result.OutputFiles.OutputHtmlFile = Join-Path $TestDrive 'older.html'
    { Get-MaesterAssessmentEvidence -Output $result -JunitPath $junit -TestsPath $testsPath -ReportPath $report } | Should -Throw '*reportMismatch*'
  }
  It 'rejects missing and duplicate result objects' {
    foreach ($output in @(@(), @($result,$result))) {
      { Get-MaesterAssessmentEvidence -Output $output -JunitPath $junit -TestsPath $testsPath -ReportPath $report } | Should -Throw '*resultMissingOrAmbiguous*'
    }
  }
  It 'rejects invalid <case> count' -ForEach @(
    @{ case='negative'; value=-1 }, @{ case='fraction'; value=1.5 }, @{ case='string'; value='1' }, @{ case='boolean'; value=$true }, @{ case='missing'; value=$null }
  ) {
    $result.PassedCount = $value
    { Get-MaesterAssessmentEvidence -Output $result -JunitPath $junit -TestsPath $testsPath -ReportPath $report } | Should -Throw '*invalidCount*'
  }
  It 'rejects row/accounting mismatch and unknown labels' {
    $result.Tests[0].Result = 'Unknown'
    { Get-MaesterAssessmentEvidence -Output $result -JunitPath $junit -TestsPath $testsPath -ReportPath $report } | Should -Throw '*countMismatch*'
  }
  It 'rejects zero discovery even with nonempty HTML' {
    $result.Tests = @(); $result.TotalCount = 0; $result.PassedCount = 0; $result.FailedCount = 0; $result.SkippedCount = 0; $result.NotRunCount = 0
    Set-Content $junit '<testsuites tests="0" errors="0" failures="0" disabled="0" />'
    { Get-MaesterAssessmentEvidence -Output $result -JunitPath $junit -TestsPath $testsPath -ReportPath $report } | Should -Throw '*countMismatch*'
  }
  It 'rejects the previously false-green aggregate even with valid HTML' {
    $result.Tests = @(foreach ($pair in @(@('Passed',93),@('Failed',65),@('Error',23),@('Skipped',256),@('NotRun',300))) {
      for ($i=0; $i -lt $pair[1]; $i++) { [pscustomobject]@{ Id = "$($pair[0])-$i"; Result = $pair[0] } }
    })
    $result.TotalCount=737; $result.PassedCount=93; $result.FailedCount=65; $result.ErrorCount=23; $result.SkippedCount=256; $result.NotRunCount=300
    { Get-MaesterAssessmentEvidence -Output $result -JunitPath $junit -TestsPath $testsPath -ReportPath $report } | Should -Throw '*maesterErrors*'
  }
  It 'rejects missing, duplicate, skipped or wrong-path core cases' -ForEach @('missing','duplicate','skipped','path') {
    switch ($_) {
      'missing' { $result.Tests[0].Id = 'other' }
      'duplicate' { $result.Tests[1].Id = 'MT.1068' }
      'skipped' { $result.Tests[0].Result='Skipped'; $result.PassedCount=0; $result.SkippedCount=2 }
      'path' { $result.Tests[0].ScriptBlockFile=Join-Path $testsPath 'elsewhere.ps1' }
    }
    { Get-MaesterAssessmentEvidence -Output $result -JunitPath $junit -TestsPath $testsPath -ReportPath $report } | Should -Throw '*coreNotExecuted*'
  }
  It 'rejects malformed, absent, unsafe and inconsistent JUnit <_>' -ForEach @('missing','malformed','doctype','duplicate-root','negative','missing-count','total','engine') {
    switch ($_) {
      'missing' { Remove-Item $junit }
      'malformed' { Set-Content $junit '<testsuites' }
      'doctype' { Set-Content $junit '<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><testsuites tests="5" errors="0" failures="1" disabled="3">&x;</testsuites>' }
      'duplicate-root' { Set-Content $junit '<testsuites/><testsuites/>' }
      'negative' { Set-Content $junit '<testsuites tests="5" errors="-1" failures="1" disabled="3" />' }
      'missing-count' { Set-Content $junit '<testsuites tests="5" errors="0" />' }
      'total' { Set-Content $junit '<testsuites tests="4" errors="0" failures="1" disabled="3" />' }
      'engine' { Set-Content $junit '<testsuites tests="5" errors="1" failures="1" disabled="3" />' }
    }
    { Get-MaesterAssessmentEvidence -Output $result -JunitPath $junit -TestsPath $testsPath -ReportPath $report } | Should -Throw '*assessment.junit*'
  }
  It 'classifies every real Pester error record for <_>' -ForEach @('assertion','skip','io','unauthorized','mixed','investigate-runtime') {
    $case = $_
    $suite = Join-Path $TestDrive 'classification.Tests.ps1'
    $body = switch ($case) {
      'assertion' { '1 | Should -Be 2' }
      'skip' { "Set-ItResult -Skipped -Because 'expected exclusion'" }
      'io' { "throw [IO.IOException]::new('offline I/O failure')" }
      'unauthorized' { "throw [UnauthorizedAccessException]::new('offline access failure')" }
      'mixed' { "1 | Should -Be 2 -ErrorAction Continue; throw [IO.IOException]::new('offline mixed failure')" }
      'investigate-runtime' { "throw [IO.IOException]::new('offline investigate failure')" }
    }
    Set-Content $suite "Describe 'classification' { It 'sample' { $body } }"
    $config = New-PesterConfiguration
    $config.Run.Path = $suite; $config.Run.PassThru = $true; $config.Output.Verbosity = 'None'
    $actual = Invoke-Pester -Configuration $config
    if ($case -eq 'skip') {
      $result.Tests[2].ErrorRecord = $actual.Tests[0].ErrorRecord
      (Get-MaesterAssessmentEvidence -Output $result -JunitPath $junit -TestsPath $testsPath -ReportPath $report).Outcome | Should -Be 'Completed'
    }
    elseif ($case -eq 'assertion') {
      $result.Tests[1].ErrorRecord = $actual.Tests[0].ErrorRecord
      (Get-MaesterAssessmentEvidence -Output $result -JunitPath $junit -TestsPath $testsPath -ReportPath $report).Outcome | Should -Be 'Completed'
    }
    else {
      if ($case -eq 'mixed') { @($actual.Tests[0].ErrorRecord).Count | Should -BeGreaterThan 1 }
      if ($case -eq 'investigate-runtime') {
        $result.Tests[2].Result = 'Investigate'; $result.SkippedCount = 0; $result.InvestigateCount = 1
        $result.Tests[2].ErrorRecord = $actual.Tests[0].ErrorRecord
      }
      else { $result.Tests[1].ErrorRecord = $actual.Tests[0].ErrorRecord }
      { Get-MaesterAssessmentEvidence -Output $result -JunitPath $junit -TestsPath $testsPath -ReportPath $report } | Should -Throw '*unclassifiedFailure*'
    }
  }
  It 'rejects real Pester 6.2 discovery and BeforeAll failures from root errors' -ForEach @('discovery','setup') {
    $suite = Join-Path $TestDrive "$_-fixture.Tests.ps1"
    Set-Content $suite $(if ($_ -eq 'discovery') { "throw 'offline discovery error'" } else { "Describe 'setup' { BeforeAll { throw 'offline setup error' }; It 'unreachable' { 1 | Should -Be 1 } }" })
    $config = New-PesterConfiguration
    $config.Run.Path = $suite; $config.Run.PassThru = $true
    $config.Output.Verbosity = 'None'; $config.TestResult.Enabled = $true; $config.TestResult.OutputPath = $junit; $config.TestResult.OutputFormat = 'JUnitXml'
    $pester = Invoke-Pester -Configuration $config
    ($pester.FailedContainersCount + $pester.FailedBlocksCount) | Should -BeGreaterThan 0
    { Get-MaesterAssessmentEvidence -Output $result -JunitPath $junit -TestsPath $testsPath -ReportPath $report } | Should -Throw '*junitErrors*'
  }
}

Describe 'Approved pure contract parity' {
  It 'retains reviewed Container PR 51 gates except the tested 2.3.0 version pin' {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    # Original reviewed function hashes, after normalizing only the independently tested module-version pin.
    # Canonical LF function text SHA256 from Container head dacae290354121588e1ed6459b71b6d89d2193d5.
    $expected = @{
      'Get-EvidenceCount' = 'd09b86e0f6390598ef0b37840d6143ecc74a460f0365e3b6abfa9786efff0727'
      'Get-MaesterAssessmentEvidence' = 'ed8c59d66ccab0d13104ce9e6bb43327ba6b96c00e8fa383bce34cd3ce3b3f38'
    }
    foreach ($name in $expected.Keys) {
      $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
      $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($function.Extent.Text.Replace("`r`n", "`n").Replace("'2.3.0'", "'2.2.0'")))).ToLowerInvariant()
      $hash | Should -BeExactly $expected[$name]
    }
  }
}
