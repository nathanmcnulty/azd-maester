#Requires -Version 7.6
Set-StrictMode -Version Latest

# Deliberately separate framework health from policy compliance. These are two
# unconditional core tests in the locked Maester 2.3.0 suite, not a coverage claim.
$script:CoreCases = [ordered]@{
  'MT.1068' = 'Maester/Entra/Test-MtTenantCreationRestricted.Tests.ps1'
  'MT.1069' = 'Maester/Entra/Test-MtSecurityGroupCreationRestricted.Tests.ps1'
}

function Get-EvidenceCount {
  param($Value)
  if ($null -eq $Value -or $Value -is [bool] -or $Value -is [string] -or
      $Value -isnot [ValueType] -or $Value -lt 0 -or $Value -gt [int]::MaxValue -or
      [decimal]$Value -ne [math]::Truncate([decimal]$Value)) { throw 'assessment.invalidCount' }
  [int]$Value
}

function Get-MaesterAssessmentEvidence {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$Output,
    [Parameter(Mandatory)][string]$JunitPath,
    [Parameter(Mandatory)][string]$TestsPath,
    [Parameter(Mandatory)][string]$ReportPath
  )
  $ErrorActionPreference = 'Stop'
  # Ignore incidental success-stream strings, but never select one of multiple
  # result objects. No HTML/JavaScript is evaluated to recover missing evidence.
  $results = @($Output | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Tests'] })
  if ($results.Count -ne 1) { throw 'assessment.resultMissingOrAmbiguous' }
  $result = $results[0]
  if ($result.EndOfJson -isnot [string] -or $result.EndOfJson -cne 'EndOfJson' -or
      ($result.CurrentVersion -isnot [string] -and $result.CurrentVersion -isnot [version]) -or
      [string]$result.CurrentVersion -cne '2.3.0') { throw 'assessment.resultInvalid' }
  $tests = @($result.Tests)
  foreach ($test in $tests) {
    if ($null -eq $test -or $test.Result -isnot [string]) { throw 'assessment.resultInvalid' }
  }
  $counts = [ordered]@{}
  foreach ($state in 'Passed','Failed','Error','Investigate','Skipped','NotRun') {
    $name = $state + 'Count'
    $counts[$name] = Get-EvidenceCount $result.$name
    if ($counts[$name] -ne @($tests | Where-Object Result -CEQ $state).Count) { throw 'assessment.countMismatch' }
  }
  $counts.TotalCount = Get-EvidenceCount $result.TotalCount
  $sum = 0L
  foreach ($state in 'Passed','Failed','Error','Investigate','Skipped','NotRun') { $sum += $counts[$state + 'Count'] }
  if ($sum -ne $counts.TotalCount -or $tests.Count -ne $counts.TotalCount -or $sum -eq 0) { throw 'assessment.countMismatch' }
  if ($counts.ErrorCount -ne 0) { throw 'assessment.maesterErrors' }
  # Maester reclassifies only selected exception types. An IOException or a
  # mixed assertion/runtime error can still be labelled Failed (or Investigate).
  # Check every record, never only the first, using Pester's stable marker IDs.
  foreach ($test in $tests) {
    if (-not $test.PSObject.Properties['ErrorRecord']) { throw 'assessment.errorRecordsMissing' }
    $records = @($test.ErrorRecord | Where-Object { $null -ne $_ })
    $allowed = switch ($test.Result) {
      'Failed' { @('PesterAssertionFailed') }
      'Skipped' { @('PesterTestSkipped') }
      'Investigate' { @('PesterAssertionFailed','PesterTestSkipped','PesterTestInconclusive') }
      default { @() }
    }
    if ($test.Result -ceq 'Failed' -and $records.Count -eq 0) { throw 'assessment.unclassifiedFailure' }
    foreach ($record in $records) {
      if ($record.FullyQualifiedErrorId -isnot [string] -or $record.FullyQualifiedErrorId -cnotin $allowed) { throw 'assessment.unclassifiedFailure' }
    }
  }
  $core = [ordered]@{}
  foreach ($id in $script:CoreCases.Keys) {
    $matches = @($tests | Where-Object Id -CEQ $id)
    $expectedPath = [IO.Path]::GetFullPath((Join-Path $TestsPath $script:CoreCases[$id]))
    if ($matches.Count -ne 1 -or $matches[0].Result -cnotin @('Passed','Failed') -or
        [string]::IsNullOrWhiteSpace($matches[0].ScriptBlockFile) -or
        [IO.Path]::GetFullPath($matches[0].ScriptBlockFile) -cne $expectedPath) { throw 'assessment.coreNotExecuted' }
    $core[$id] = $matches[0].Result
  }
  $reader = $null
  try {
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 16777216
    $reader = [Xml.XmlReader]::Create($JunitPath, $settings)
    $document = [Xml.XmlDocument]::new()
    $document.XmlResolver = $null
    $document.Load($reader)
    $root = $document.DocumentElement
    if ($null -eq $root -or $root.get_Name() -cne 'testsuites') { throw 'assessment.junitInvalid' }
    $junit = [ordered]@{}
    foreach ($name in 'tests','errors','failures','disabled') {
      $n = 0
      if (-not $root.HasAttribute($name) -or $root.GetAttribute($name) -cnotmatch '^(0|[1-9][0-9]*)\z' -or
          -not [int]::TryParse($root.GetAttribute($name), [ref]$n)) { throw 'assessment.junitInvalid' }
      $junit[$name] = $n
    }
  }
  catch { throw 'assessment.junitInvalid' }
  finally { if ($null -ne $reader) { $reader.Dispose() } }
  # Pester 6.2.0 root errors = FailedContainersCount + FailedBlocksCount.
  # Maester can reclassify Pester failures/skips as Investigate, so do not equate
  # every Pester failure with a policy finding or reject expected exclusions.
  if ($junit.errors -ne 0) { throw 'assessment.junitErrors' }
  if ($junit.tests -ne $counts.TotalCount -or
      $junit.failures -lt $counts.FailedCount -or $junit.failures -gt ($counts.FailedCount + $counts.InvestigateCount) -or
      $junit.disabled -lt ($counts.SkippedCount + $counts.NotRunCount) -or
      $junit.disabled -gt ($counts.SkippedCount + $counts.NotRunCount + $counts.InvestigateCount) -or
      (($junit.failures - $counts.FailedCount) + ($junit.disabled - $counts.SkippedCount - $counts.NotRunCount)) -gt $counts.InvestigateCount -or
      ($junit.failures + $junit.disabled) -gt $junit.tests) { throw 'assessment.junitCountMismatch' }
  if ([string]::IsNullOrWhiteSpace($result.OutputFiles.OutputHtmlFile) -or [IO.Path]::GetFullPath($result.OutputFiles.OutputHtmlFile) -cne [IO.Path]::GetFullPath($ReportPath)) { throw 'assessment.reportMismatch' }
  if (-not (Test-Path -LiteralPath $ReportPath -PathType Leaf) -or (Get-Item -LiteralPath $ReportPath).Length -le 0) { throw 'assessment.reportMissing' }
  [ordered]@{
    Outcome = 'Completed'; Counts = $counts; CoreCases = $core
    JunitErrors = $junit.errors; JunitTests = $junit.tests
    ReportSha256 = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash.ToLowerInvariant()
    JunitSha256 = (Get-FileHash -LiteralPath $JunitPath -Algorithm SHA256).Hash.ToLowerInvariant()
  }
}


Export-ModuleMember -Function Get-MaesterAssessmentEvidence
