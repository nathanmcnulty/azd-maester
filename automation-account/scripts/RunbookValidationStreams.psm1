Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-MaesterAutomationJobStreamSummary {
  [CmdletBinding()]
  param(
    [AllowEmptyCollection()]
    [object[]]$Streams = @(),

    [scriptblock]$DetailResolver
  )

  $counts = [ordered]@{
    Output = 0
    Warning = 0
    Error = 0
    Progress = 0
    Debug = 0
    Verbose = 0
    Other = 0
  }
  $messages = @()
  $actionableTypes = @('Output', 'Warning', 'Error')

  foreach ($stream in $Streams) {
    $streamType = [string]$stream.properties.streamType
    if ($counts.Contains($streamType)) {
      $counts[$streamType]++
    }
    else {
      $counts.Other++
    }

    if ($streamType -notin $actionableTypes) {
      continue
    }

    $message = [string]$stream.properties.summary
    if ([string]::IsNullOrWhiteSpace($message)) {
      $message = [string]$stream.properties.streamText
    }

    if ([string]::IsNullOrWhiteSpace($message) -and $DetailResolver) {
      $detail = & $DetailResolver $stream
      if ($detail -and $detail.properties) {
        $message = [string]$detail.properties.summary
        if ([string]::IsNullOrWhiteSpace($message)) {
          $message = [string]$detail.properties.streamText
        }
      }
    }

    if (-not [string]::IsNullOrWhiteSpace($message)) {
      $messages += [pscustomobject]@{
        Type = $streamType
        Message = $message
      }
    }
  }

  [pscustomobject]@{
    Counts = [pscustomobject]$counts
    Messages = @($messages)
    OmittedCount = $counts.Progress + $counts.Debug + $counts.Verbose + $counts.Other
  }
}

Export-ModuleMember -Function Get-MaesterAutomationJobStreamSummary
