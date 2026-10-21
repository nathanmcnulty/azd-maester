#Requires -Version 7.6
BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent
    $lock = Get-Content (Join-Path $root 'runtime-packages.lock.json') -Raw | ConvertFrom-Json
    $runner = Get-Content (Join-Path $root 'src/MaesterTimerTrigger/run.ps1') -Raw
}
Describe 'Retained Function 2.3 runtime integration' {
    It 'pins exactly the reviewed Maester package and hash' {
        $entries = @($lock.packages | Where-Object name -eq 'Maester')
        $entries.Count | Should -Be 1
        $entries[0].version | Should -BeExactly '2.3.0'
        $entries[0].sha256 | Should -BeExactly '95F720822D04271F5E15F4665BC017111DC72E17B97E5D0525CB4EC2FF5BD0B0'
        $runner | Should -Match "Import-LockedModule -Name 'Maester' -Version '2\.3\.0'"
        $runner | Should -Not -Match "'2\.2\.0'"
    }
    It 'ships the evidence gate in the existing recursively staged Function source tree' {
        Test-Path (Join-Path $root 'src/Maester.AssessmentEvidence.psm1') -PathType Leaf | Should -BeTrue
        $deploy = Get-Content (Join-Path $root 'scripts/Deploy-FunctionCode.ps1') -Raw
        $deploy | Should -Match 'Copy-Item -Path \$srcPath -Destination \$stagingPath -Recurse -Force'
        $runner | Should -Match "Import-Module .*'Maester.AssessmentEvidence.psm1'"
    }
    It 'keeps validation request binding while requiring assessment evidence before publication' {
        $validation = Get-Content (Join-Path $root 'src/MaesterValidationTrigger/run.ps1') -Raw
        $validation | Should -Match 'ValidationId'
        $runner | Should -Match 'ValidationId'
        $runner.IndexOf('$assessmentEvidence = Get-MaesterAssessmentEvidence') | Should -BeGreaterThan 0
        $runner.IndexOf('$assessmentEvidence = Get-MaesterAssessmentEvidence') | Should -BeLessThan $runner.IndexOf('# Publish to web app')
    }
    It 'keeps report PUT timestamps independently of the Maester result gate' {
        $runner | Should -Match "'x-ms-date'\s*=\s*\[datetime\]::UtcNow.ToString\('R'"
    }
}
