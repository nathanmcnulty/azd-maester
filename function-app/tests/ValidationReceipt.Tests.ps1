BeforeAll {
  Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/FunctionValidation.Core.psm1') -Force
}

Describe 'Current invocation receipt' {
  BeforeEach {
    $script:id = [guid]::NewGuid()
    $script:receipt = [pscustomobject]@{
      schemaVersion = 1
      validationId = $script:id.ToString('D')
      invocationId = [guid]::NewGuid().ToString('D')
      status = 'Succeeded'
    }
  }

  It 'accepts a completed run with this request and an invocation identity' {
    Assert-MaesterValidationReceipt -Receipt $script:receipt -ValidationId $script:id | Should -BeTrue
  }
  It 'rejects a stale or unrelated request receipt' {
    $script:receipt.validationId = [guid]::NewGuid().ToString('D')
    { Assert-MaesterValidationReceipt -Receipt $script:receipt -ValidationId $script:id } | Should -Throw '*mismatched invocation identity*'
  }
  It 'rejects a missing invocation identity' {
    $script:receipt.invocationId = $null
    { Assert-MaesterValidationReceipt -Receipt $script:receipt -ValidationId $script:id } | Should -Throw '*mismatched invocation identity*'
  }
  It 'rejects a failed run' {
    $script:receipt.status = 'Failed'
    { Assert-MaesterValidationReceipt -Receipt $script:receipt -ValidationId $script:id } | Should -Throw '*failed*'
  }
  It 'rejects an unknown completion state' {
    $script:receipt.status = 'Running'
    { Assert-MaesterValidationReceipt -Receipt $script:receipt -ValidationId $script:id } | Should -Throw '*unknown status*'
  }
}
