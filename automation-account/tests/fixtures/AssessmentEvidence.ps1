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
function New-TestAutomationReceipt {
  param([string]$JobId = '11111111-1111-4111-8111-111111111111')
  [ordered]@{
    SchemaVersion = 1; Kind = 'MaesterAutomationAssessment'; RequestedJobId = $JobId
    StartedAt = [datetimeoffset]::UtcNow.ToString('o'); CompletedAt = [datetimeoffset]::UtcNow.ToString('o')
    Runtime = @{ PowerShell = '7.6.0-preview.5'; DotNet = '10.0.9'; Edition = 'Core'; Modules = @{ 'NuGet' = '1.3.3'; 'PackageManagement' = '1.4.8.1'; 'PowerShellGet' = '2.2.5'; 'Az.Accounts' = '5.5.3'; 'Microsoft.Graph.Authentication' = '2.41.0'; Pester = '6.2.0'; Maester = '2.3.0' } }
    Assessment = @{ Outcome = 'Completed'; Counts = @{ TotalCount = 5; PassedCount = 1; FailedCount = 1; ErrorCount = 0; InvestigateCount = 0; SkippedCount = 1; NotRunCount = 2 }; CoreCases = @{ 'MT.1068' = 'Passed'; 'MT.1069' = 'Failed' }; JunitErrors = 0; JunitTests = 5; ReportSha256 = 'a' * 64; JunitSha256 = 'b' * 64 }
    Publication = @{ Archive = 'Published'; Latest = 'Published'; WebApp = 'Disabled'; Mail = 'Disabled' }
  }
}
function New-TestRuntimeReceipt {
  $r = New-TestAutomationReceipt
  [ordered]@{
    Kind = 'Maester.RuntimeValidation'; SchemaVersion = 1
    PowerShellVersion = $r.Runtime.PowerShell; DotNetVersion = $r.Runtime.DotNet
    Modules = @(foreach ($name in $r.Runtime.Modules.Keys) { @{ Name = $name; Version = $r.Runtime.Modules[$name]; Path = "/tmp/private/$name/module.psm1"; ModuleBase = "/tmp/private/$name" } })
  }
}
