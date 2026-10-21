function New-TestAssessmentResult {
  param([string]$TestsPath)
  [pscustomobject]@{
    EndOfJson = 'EndOfJson'; CurrentVersion = [version]'2.3.0'; TotalCount = 5
    PassedCount = 1; FailedCount = 1; ErrorCount = 0; InvestigateCount = 0; SkippedCount = 1; NotRunCount = 2
    Tests = @(
      [pscustomobject]@{ Id = 'MT.1068'; Result = 'Passed'; ErrorRecord = @(); ScriptBlockFile = (Join-Path $TestsPath 'Maester/Entra/Test-MtTenantCreationRestricted.Tests.ps1') }
      [pscustomobject]@{ Id = 'MT.1069'; Result = 'Failed'; ErrorRecord = @([pscustomobject]@{ FullyQualifiedErrorId = 'PesterAssertionFailed' }); ScriptBlockFile = (Join-Path $TestsPath 'Maester/Entra/Test-MtSecurityGroupCreationRestricted.Tests.ps1') }
      [pscustomobject]@{ Id = 'optional'; Result = 'Skipped'; ErrorRecord = @([pscustomobject]@{ FullyQualifiedErrorId = 'PesterTestSkipped' }); ScriptBlockFile = '' }
      [pscustomobject]@{ Id = 'preview'; Result = 'NotRun'; ErrorRecord = @(); ScriptBlockFile = '' }
      [pscustomobject]@{ Id = 'long'; Result = 'NotRun'; ErrorRecord = @(); ScriptBlockFile = '' }
    )
  }
}
