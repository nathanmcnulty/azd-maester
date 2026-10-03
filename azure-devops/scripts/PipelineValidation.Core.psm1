Set-StrictMode -Version Latest

function Get-RecordProperty {
  param($Record, [string]$Name)
  if ($null -eq $Record) { return $null }
  $property = $Record.PSObject.Properties | Where-Object Name -EQ $Name | Select-Object -First 1
  if ($property) { return $property.Value }
  return $null
}

function Test-ExpectedMaesterFinding {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Organization,
    [Parameter(Mandatory)][string]$Project,
    [Parameter(Mandatory)][string]$RunId
  )

  # A failed build is acceptable only when the Maester runner is its sole
  # failed task and both result publishers succeed. Never infer this from a
  # marker in an unrelated build log.
  $buildUri = "https://dev.azure.com/$Organization/$Project/_apis/build/builds/$RunId"
  $timeline = Invoke-ADOPSRestMethod -Method GET -Uri "$buildUri/timeline?api-version=7.1"
  $records = @(Get-RecordProperty $timeline 'records')
  if ($records.Count -eq 0 -or $null -eq $records[0]) { return $false }

  $requiredNames = @('Run Maester', 'Publish Maester Html Report', 'Publish Pester Test Results')
  $tasks = @($records | Where-Object { (Get-RecordProperty $_ 'type') -eq 'Task' })
  $jobs = @($records | Where-Object { (Get-RecordProperty $_ 'type') -eq 'Job' })
  if ($jobs.Count -ne 1 -or (Get-RecordProperty $jobs[0] 'name') -notin @('MaesterRun', 'Maester Run')) { return $false }
  foreach ($name in $requiredNames) {
    if (@($tasks | Where-Object { (Get-RecordProperty $_ 'name') -eq $name }).Count -ne 1) { return $false }
  }

  foreach ($record in $records) {
    $result = [string](Get-RecordProperty $record 'result')
    $state = [string](Get-RecordProperty $record 'state')
    if ($state -ne 'completed' -or $result -in @('canceled', 'abandoned', 'skipped', 'succeededWithIssues')) { return $false }
    if ($result -eq 'failed' -and (Get-RecordProperty $record 'type') -eq 'Task' -and
      (Get-RecordProperty $record 'name') -ne 'Run Maester') { return $false }
    if ($result -notin @('succeeded', 'failed')) { return $false }
  }

  $runner = @($tasks | Where-Object { (Get-RecordProperty $_ 'name') -eq 'Run Maester' })[0]
  $htmlPublisher = @($tasks | Where-Object { (Get-RecordProperty $_ 'name') -eq 'Publish Maester Html Report' })[0]
  $testPublisher = @($tasks | Where-Object { (Get-RecordProperty $_ 'name') -eq 'Publish Pester Test Results' })[0]
  if ((Get-RecordProperty $htmlPublisher 'result') -ne 'succeeded') { return $false }
  if ((Get-RecordProperty $testPublisher 'result') -ne 'succeeded') { return $false }
  if ((Get-RecordProperty $runner 'result') -ne 'failed') { return $false }

  $artifacts = Invoke-ADOPSRestMethod -Method GET -Uri "$buildUri/artifacts?api-version=7.1"
  if (@((Get-RecordProperty $artifacts 'value') | Where-Object { (Get-RecordProperty $_ 'name') -eq 'TestResults' }).Count -ne 1) { return $false }

  $log = Get-RecordProperty $runner 'log'
  $logUrl = [string](Get-RecordProperty $log 'url')
  if ([string]::IsNullOrWhiteSpace($logUrl)) { return $false }
  $runnerLog = [string](Invoke-ADOPSRestMethod -Method GET -Uri $logUrl)
  return $runnerLog -match 'AZD_MAESTER_RESULT=FINDINGS;FAILED=[1-9][0-9]*'
}

Export-ModuleMember -Function Test-ExpectedMaesterFinding
