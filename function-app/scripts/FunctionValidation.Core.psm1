Set-StrictMode -Version Latest

function Assert-MaesterValidationReceipt {
  param(
    [Parameter(Mandatory)]$Receipt,
    [Parameter(Mandatory)][guid]$ValidationId
  )
  $expected = $ValidationId.ToString('D')
  $actual = [guid]::Empty
  $invocation = [guid]::Empty
  if ($Receipt.schemaVersion -ne 1 -or
      -not [guid]::TryParse([string]$Receipt.validationId, [ref]$actual) -or $actual -ne $ValidationId -or
      -not [guid]::TryParse([string]$Receipt.invocationId, [ref]$invocation) -or $invocation -eq [guid]::Empty) {
    throw "Validation receipt for '$expected' has missing or mismatched invocation identity."
  }
  if ($Receipt.status -eq 'Failed') { throw "Validation invocation '$expected' failed." }
  if ($Receipt.status -ne 'Succeeded') { throw "Validation receipt for '$expected' has unknown status '$($Receipt.status)'." }
  return $true
}

Export-ModuleMember -Function Assert-MaesterValidationReceipt
