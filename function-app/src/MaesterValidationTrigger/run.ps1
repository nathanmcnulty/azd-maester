param([string]$ValidationRequest, $TriggerMetadata)

# The admin API passes a one-use request ID to this dedicated trigger. Scheduled
# timer invocations cannot publish a receipt for the validation request.
$parsed = [guid]::Empty
if (-not [guid]::TryParse($ValidationRequest, [ref]$parsed) -or $parsed -eq [guid]::Empty) {
  throw 'Validation trigger requires a nonempty GUID request ID.'
}

& (Join-Path $PSScriptRoot '../MaesterTimerTrigger/run.ps1') `
  -Timer @{ IsPastDue = $false } -TriggerMetadata $TriggerMetadata -ValidationId $parsed.ToString('D')
