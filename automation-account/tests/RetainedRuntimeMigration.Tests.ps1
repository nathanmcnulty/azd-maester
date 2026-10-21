#Requires -Version 7.6
BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent
    $runbook = Get-Content (Join-Path $root 'scripts/Invoke-MaesterAutomationRunbook.ps1') -Raw
    $infra = Get-Content (Join-Path $root 'infra/main.bicep') -Raw
}
Describe 'Retained Automation 2.3 runtime integration' {
    It 'pins the reviewed 2.3 package in both infrastructure and the local byte verifier' {
        $infra | Should -Match "package/Maester/2\.3\.0'"
        $runbook | Should -Match "'Maester' = @\{ Version = '2\.3\.0'; Sha256 = '95F720822D04271F5E15F4665BC017111DC72E17B97E5D0525CB4EC2FF5BD0B0'"
        $runbook | Should -Not -Match "'2\.2\.0'"
        $runbook | Should -Match '\$_.Path.StartsWith\(\$verifiedModuleRoot'
    }
    It 'updates the immutable seed without scheduling that seed' {
        $infra | Should -Match 'maester365/maester/7413c42d3fcc724dfea94d2726e690ddd364d914/powershell/public/Invoke-Maester.ps1'
        $infra | Should -Match '87CEB74D50309360C592816BFC963A6D370B66C51AE71D45A01117651BF7F5A8'
        $infra | Should -Not -Match 'resource\s+jobSchedule\s+'
    }
    It 'embeds the assessment gate before publication without adding runtime validation or diagnostic modes' {
        $runbook | Should -Match '# BEGIN shared pure assessment health contract'
        $runbook.IndexOf('$assessmentEvidence = Get-MaesterAssessmentEvidence') | Should -BeGreaterThan 0
        $runbook.IndexOf('$assessmentEvidence = Get-MaesterAssessmentEvidence') | Should -BeLessThan $runbook.IndexOf('# Upload results to storage')
        $runbook | Should -Not -Match 'Publish-FailedAssessmentArtifacts|RuntimeValidationOnly|MAESTER_ASSESSMENT_RECEIPT_V1:'
    }
    It 'adds Blob request dates while leaving existing optional mail explicitly unverified' {
        $runbook | Should -Match "'x-ms-date'\s*=\s*\[datetime\]::UtcNow.ToString\('R'"
        $runbook | Should -Match 'Upstream inline email is configured; delivery is unverified'
    }
}
