BeforeAll {
    $runner = Get-Content (Join-Path $PSScriptRoot '../scripts/Invoke-MaesterAutomationRunbook.ps1') -Raw
    $start = $runner.IndexOf('$previousDriftRoot =')
    $end = $runner.IndexOf('$assessmentEvidence = Get-MaesterAssessmentEvidence', $start)
    if ($start -lt 0 -or $end -le $start) { throw 'Production invocation boundary not found.' }
    $invokeBlock = [scriptblock]::Create($runner.Substring($start, $end - $start))
    function Invoke-Maester {
        [CmdletBinding()]
        param()
        $script:invocations++
        switch ($script:mode) {
            'emitted-error' { Write-Error 'synthetic emitted error' -ErrorAction Continue }
            'terminating' { throw [IO.IOException]::new('synthetic terminating error') }
            'caught-assertion' { try { 1 | Should -Be 2 -ErrorAction Stop } catch { } }
            'caught-probe' { try { Get-Command UnavailableOptionalWorkloadForFixture -ErrorAction Stop } catch { } }
            'returned-error-record' { [Management.Automation.ErrorRecord]::new([IO.IOException]::new('synthetic record'), 'synthetic', [Management.Automation.ErrorCategory]::NotSpecified, $null) }
        }
        'incidental output'
        $script:expectedResult
    }
}
Describe 'Actual emitted error stream boundary' {
    BeforeEach {
        $script:invocations = 0
        $script:expectedResult = [pscustomobject]@{ Tests = @(); Marker = 'single result instance' }
        $maesterInvokeParameters = @{}
        $savedDrift = [Environment]::GetEnvironmentVariable('MAESTER_FOLDER_DRIFT','Process')
        [Environment]::SetEnvironmentVariable('MAESTER_FOLDER_DRIFT','inherited-fixture','Process')
    }
    AfterEach {
        $script:invocations | Should -Be 1
        [Environment]::GetEnvironmentVariable('MAESTER_FOLDER_DRIFT','Process') | Should -BeExactly 'inherited-fixture'
        [Environment]::SetEnvironmentVariable('MAESTER_FOLDER_DRIFT', $(if ($null -eq $savedDrift) { [Management.Automation.Language.NullString]::Value } else { $savedDrift }), 'Process')
    }
    It 'preserves one result and ignores internally handled control flow: <_>' -ForEach @('normal','caught-assertion','caught-probe') {
        $script:mode = $_
        . $invokeBlock
        @($invocationErrors).Count | Should -Be 0
        @($maesterOutput).Count | Should -Be 2
        $maesterOutput[0] | Should -BeExactly 'incidental output'
        [object]::ReferenceEquals($maesterOutput[1], $script:expectedResult) | Should -BeTrue
    }
    It 'rejects emitted nonterminating error even when valid output follows' {
        $script:mode = 'emitted-error'
        { . $invokeBlock } | Should -Throw '*assessment.invocationErrors*'
    }
    It 'rejects an ErrorRecord returned on the success stream rather than dropping it' {
        $script:mode = 'returned-error-record'
        { . $invokeBlock } | Should -Throw '*assessment.invocationErrors*'
    }
    It 'rejects a terminating exception' {
        $script:mode = 'terminating'
        { . $invokeBlock } | Should -Throw '*assessment.invokeFailed*'
    }
}
