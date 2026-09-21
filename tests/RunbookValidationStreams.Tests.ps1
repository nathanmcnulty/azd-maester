$repoRoot = Split-Path -Parent $PSScriptRoot
$streamModule = Join-Path $repoRoot 'automation-account\scripts\RunbookValidationStreams.psm1'

Import-Module $streamModule -Force

Describe 'Automation runbook validation stream summary' {
  It 'retains actionable messages and omits noisy streams without detail requests' {
    $streams = @(
      [pscustomobject]@{ properties = [pscustomobject]@{ streamType = 'Progress'; summary = 'Running tests'; streamText = $null } },
      [pscustomobject]@{ properties = [pscustomobject]@{ streamType = 'Output'; summary = 'Report uploaded'; streamText = $null } },
      [pscustomobject]@{ properties = [pscustomobject]@{ streamType = 'Warning'; summary = $null; streamText = 'Permission-limited coverage' } },
      [pscustomobject]@{ properties = [pscustomobject]@{ streamType = 'Error'; summary = $null; streamText = $null; jobStreamId = 'error-stream' } },
      [pscustomobject]@{ properties = [pscustomobject]@{ streamType = 'Debug'; summary = 'internal detail'; streamText = $null } }
    )
    $detailRequests = [System.Collections.Generic.List[string]]::new()

    $result = Get-MaesterAutomationJobStreamSummary -Streams $streams -DetailResolver {
      param($stream)
      $detailRequests.Add($stream.properties.jobStreamId)
      [pscustomobject]@{ properties = [pscustomobject]@{ summary = 'Forbidden'; streamText = $null } }
    }

    $result.Messages.Count | Should -Be 3
    $result.Messages.Type | Should -Be @('Output', 'Warning', 'Error')
    $result.Messages.Message | Should -Be @('Report uploaded', 'Permission-limited coverage', 'Forbidden')
    $result.Counts.Progress | Should -Be 1
    $result.Counts.Debug | Should -Be 1
    $result.OmittedCount | Should -Be 2
    $detailRequests | Should -Be @('error-stream')
  }

  It 'handles a job with no streams' {
    $result = Get-MaesterAutomationJobStreamSummary -Streams @()

    $result.Messages | Should -BeNullOrEmpty
    $result.OmittedCount | Should -Be 0
    $result.Counts.Error | Should -Be 0
  }
}
