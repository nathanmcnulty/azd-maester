$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptFiles = Get-ChildItem -LiteralPath $repoRoot -Recurse -File -Include *.ps1, *.psm1 |
  Where-Object { $_.FullName -notmatch '[\\/](?:\.git|tests)[\\/]' }

Import-Module (Join-Path $repoRoot 'shared\scripts\Maester-SetupHelpers.psm1') -Force

Describe 'Azure CLI target context' {
  It 'does not mutate the global default subscription' {
    $matches = $scriptFiles | Select-String -Pattern '\baz account set\b'
    $matches | Should -BeNullOrEmpty
  }

  It 'targets every access token request explicitly' {
    $matches = $scriptFiles | Select-String -Pattern '\baz account get-access-token\b'
    foreach ($match in $matches) {
      $match.Line | Should -Match '--(?:subscription|tenant)\b'
    }
  }

  It 'targets every Azure CLI REST request explicitly' {
    $matches = $scriptFiles | Select-String -Pattern '\baz rest\b'
    foreach ($match in $matches) {
      $match.Line | Should -Match '(?:--subscription\b|@subscriptionArgs\b)'
    }
  }
}

Describe 'Selected subscription validation' {
  InModuleScope Maester-SetupHelpers {
    BeforeEach {
      Mock az {
        $global:LASTEXITCODE = 0
        '[{"id":"11111111-1111-1111-1111-111111111111","tenantId":"22222222-2222-2222-2222-222222222222"}]'
      }
    }

    It 'returns the requested subscription without changing the default' {
      $account = Get-AzCliSubscriptionContext `
        -SubscriptionId '11111111-1111-1111-1111-111111111111' `
        -TenantId '22222222-2222-2222-2222-222222222222'

      $account.id | Should -Be '11111111-1111-1111-1111-111111111111'
      Should -Invoke az -Times 1 -Exactly
    }

    It 'rejects a subscription from a different tenant' {
      {
        Get-AzCliSubscriptionContext `
          -SubscriptionId '11111111-1111-1111-1111-111111111111' `
          -TenantId '33333333-3333-3333-3333-333333333333'
      } | Should -Throw '*belongs to tenant*'
    }
  }
}
