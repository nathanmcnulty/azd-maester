BeforeAll {
  . (Join-Path $PSScriptRoot '../scripts/JobScheduleOwnership.ps1')
  Import-Module (Join-Path $PSScriptRoot '../scripts/Resolve-DeploymentTarget.psm1') -Force
  $script:hookPath = Join-Path $PSScriptRoot '../scripts/Run-AzdPreProvision.ps1'
  $script:accountId = '/subscriptions/sub-test/resourceGroups/rg-test/providers/Microsoft.Automation/automationAccounts/aa-test'
  $script:principalId = '11111111-1111-1111-1111-111111111111'
  $script:scheduleId = '22222222-2222-2222-2222-222222222222'
  $script:unrelatedId = '33333333-3333-3333-3333-333333333333'
  $script:account = [pscustomobject]@{ id = $script:accountId; identity = @{ principalId = $script:principalId } }
  $script:owned = [pscustomobject]@{ name = $script:scheduleId; properties = @{ jobScheduleId = $script:scheduleId; schedule = @{ name = 'maester-weekly-sunday' }; runbook = @{ name = 'maester-runbook' } } }
  $script:unrelated = [pscustomobject]@{ name = $script:unrelatedId; properties = @{ jobScheduleId = $script:unrelatedId; schedule = @{ name = 'other' }; runbook = @{ name = 'other' } } }

  function Invoke-OfflinePreProvision {
    param([hashtable]$Scenario)
    $names = @('AZURE_ENV_NAME', 'AZURE_SUBSCRIPTION_ID', 'AZURE_TENANT_ID', 'AZURE_LOCATION')
    $saved = @{}
    foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name) }
    try {
      $env:AZURE_ENV_NAME = 'test'
      $env:AZURE_SUBSCRIPTION_ID = 'sub-test'
      $env:AZURE_TENANT_ID = 'tenant-test'
      $env:AZURE_LOCATION = 'westus'
      $global:maesterOfflineScenario = $Scenario
      $global:maesterOfflineCalls = [Collections.Generic.List[string]]::new()
      function Import-Module { param([string]$Name, [switch]$Force) }
      function Invoke-MaesterPreProvision { param($SolutionName, $SubscriptionId, $TenantId, $Location) }
      function global:azd {
        $global:maesterOfflineCalls.Add("azd $($args -join ' ')")
        $global:LASTEXITCODE = 0
        if ($args[0] -eq 'env' -and $args[1] -eq 'get-values') {
          return ($global:maesterOfflineScenario.Values | ConvertTo-Json -Compress)
        }
        if ($args[0] -eq 'env' -and $args[1] -eq 'set') { return }
        throw "Unexpected azd call: $($args -join ' ')"
      }
      function global:az {
        $command = $args -join ' '
        $global:maesterOfflineCalls.Add("az $command")
        $global:LASTEXITCODE = 0
        if ($command -like 'group exists *') { return $global:maesterOfflineScenario.GroupExists }
        if ($command -like 'automation account list *') { return '[]' }
        if ($command -like 'rest --method GET *') {
          if ($command -like '*/jobSchedules?*') { return ($global:maesterOfflineScenario.ScheduleList | ConvertTo-Json -Depth 12 -Compress) }
          if ($command -like '*automationAccounts/aa-test?*') { return ($global:maesterOfflineScenario.Account | ConvertTo-Json -Depth 12 -Compress) }
          return ($global:maesterOfflineScenario.AccountList | ConvertTo-Json -Depth 12 -Compress)
        }
        throw "Unexpected Azure call: $command"
      }
      & $script:hookPath
    }
    finally {
      foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
      Remove-Item function:azd -ErrorAction SilentlyContinue
      Remove-Item function:az -ErrorAction SilentlyContinue
      $global:LASTEXITCODE = 0
    }
  }

  function New-OfflineScenario {
    param([string]$GroupExists = 'true')
    $values = @{ AZURE_ENV_NAME = 'test'; AZURE_SUBSCRIPTION_ID = 'sub-test'; AZURE_TENANT_ID = 'tenant-test'; AZURE_RESOURCE_GROUP = 'rg-test'; AZURE_LOCATION = 'westus' }
    $account = [pscustomobject]@{ id = $script:accountId; name = 'aa-test'; type = 'Microsoft.Automation/automationAccounts'; identity = @{ principalId = $script:principalId }; tags = @{ workload = 'maester'; solution = 'automation-account'; environment = 'test'; managedBy = 'azd' } }
    @{ Values = $values; GroupExists = $GroupExists; AccountList = @{ value = @($account) }; Account = $account; ScheduleList = @{ value = @($script:owned, $script:unrelated) } }
  }
}

Describe 'Automation jobSchedule ownership rules' {
  It 'reuses only the exact receipt-bound template association in a mixed account' {
    $result = Resolve-MaesterJobScheduleOwnership -ExpectedAccountId $script:accountId -Account $script:account `
      -JobSchedules @($script:unrelated, $script:owned) -ReceiptAccountId $script:accountId `
      -ReceiptPrincipalId $script:principalId -ReceiptJobScheduleId $script:scheduleId
    $result.JobScheduleId | Should -Be $script:scheduleId
    $result.OwnedJobScheduleId | Should -Be $script:scheduleId
  }

  It 'rejects an existing account without exact receipt or adoption' {
    { Resolve-MaesterJobScheduleOwnership -ExpectedAccountId $script:accountId -Account $script:account `
        -JobSchedules @($script:owned) } | Should -Throw '*Explicit adoption*'
  }

  It 'rejects prior receipt or adoption data when the expected account is absent' {
    { Resolve-MaesterJobScheduleOwnership -ExpectedAccountId $script:accountId -Account $null `
        -ReceiptAccountId $script:accountId -ReceiptPrincipalId $script:principalId `
        -ReceiptJobScheduleId $script:scheduleId } | Should -Throw '*no matching live account*'
    { Resolve-MaesterJobScheduleOwnership -ExpectedAccountId $script:accountId -Account $null `
        -ReceiptAccountId $script:accountId } | Should -Throw '*no matching live account*'
    { Resolve-MaesterJobScheduleOwnership -ExpectedAccountId $script:accountId -Account $null `
        -AdoptAccountId $script:accountId -AdoptPrincipalId $script:principalId `
        -AdoptJobScheduleId $script:scheduleId } | Should -Throw '*no matching live account*'
  }

  It 'rejects a wrong principal, partial receipt, ID collision, and duplicate template links' {
    { Resolve-MaesterJobScheduleOwnership -ExpectedAccountId $script:accountId -Account $script:account `
        -JobSchedules @($script:owned) -ReceiptAccountId $script:accountId -ReceiptPrincipalId $script:unrelatedId `
        -ReceiptJobScheduleId $script:scheduleId } | Should -Throw '*receipt does not match*'
    { Resolve-MaesterJobScheduleOwnership -ExpectedAccountId $script:accountId -Account $script:account `
        -JobSchedules @($script:owned) -ReceiptAccountId $script:accountId } | Should -Throw '*incomplete*'
    { Resolve-MaesterJobScheduleOwnership -ExpectedAccountId $script:accountId -Account $script:account `
        -JobSchedules @($script:unrelated) -ReceiptAccountId $script:accountId -ReceiptPrincipalId $script:principalId `
        -ReceiptJobScheduleId $script:unrelatedId } | Should -Throw '*different schedule*'
    $duplicate = [pscustomobject]@{ name = '44444444-4444-4444-4444-444444444444'; properties = @{ jobScheduleId = '44444444-4444-4444-4444-444444444444'; schedule = @{ name = 'maester-weekly-sunday' }; runbook = @{ name = 'maester-runbook' } } }
    { Resolve-MaesterJobScheduleOwnership -ExpectedAccountId $script:accountId -Account $script:account `
        -JobSchedules @($script:owned, $duplicate) -ReceiptAccountId $script:accountId `
        -ReceiptPrincipalId $script:principalId -ReceiptJobScheduleId $script:scheduleId } | Should -Throw '*More than one*'
  }

  It 'rejects an unrelated association before PUT and verifies the completed receipt' {
    { Assert-MaesterJobScheduleWriteTarget -ExpectedAccountId $script:accountId -ExpectedPrincipalId $script:principalId `
        -JobScheduleId $script:unrelatedId -Account $script:account -JobSchedules @($script:unrelated) } | Should -Throw '*another association*'
    { Assert-MaesterOwnershipReceiptTarget -ExpectedAccountId $script:accountId -ExpectedPrincipalId $script:principalId `
        -ExpectedJobScheduleId $script:scheduleId -Account $script:account -JobSchedule $script:owned } | Should -Not -Throw
    $wrongRunbook = [pscustomobject]@{ name = $script:unrelatedId; properties = @{ jobScheduleId = $script:unrelatedId; schedule = @{ name = 'maester-weekly-sunday' }; runbook = @{ name = 'other' } } }
    { Assert-MaesterJobScheduleWriteTarget -ExpectedAccountId $script:accountId -ExpectedPrincipalId $script:principalId `
        -JobScheduleId $script:scheduleId -Account $script:account -JobSchedules @($wrongRunbook) } | Should -Throw '*unexpected runbook*'
  }
}

Describe 'Preprovision hook preserves Azure state' {
  It 'generates an ID for a verified absent resource group without listing or deleting resources' {
    $scenario = New-OfflineScenario -GroupExists 'false'
    Invoke-OfflinePreProvision -Scenario $scenario
    ($global:maesterOfflineCalls -join '|') | Should -Not -Match 'rest|DELETE|lock delete'
    ($global:maesterOfflineCalls -join '|') | Should -Match 'azd env set AUTOMATION_JOB_SCHEDULE_ID [^|]+ -e test'
  }

  It 'allows a first provision before azd has recorded a resource group' {
    $scenario = New-OfflineScenario
    $scenario.Values.Remove('AZURE_RESOURCE_GROUP')
    Invoke-OfflinePreProvision -Scenario $scenario
    ($global:maesterOfflineCalls -join '|') | Should -Not -Match 'group exists|rest|DELETE'
    ($global:maesterOfflineCalls -join '|') | Should -Match 'azd env set AUTOMATION_JOB_SCHEDULE_ID [^|]+ -e test'
  }

  It 'does not discard a prior receipt when its resource group is absent' {
    $scenario = New-OfflineScenario -GroupExists 'false'
    $scenario.Values.AUTOMATION_OWNED_ACCOUNT_ID = $script:accountId
    $scenario.Values.AUTOMATION_OWNED_PRINCIPAL_ID = $script:principalId
    $scenario.Values.AUTOMATION_OWNED_JOB_SCHEDULE_ID = $script:scheduleId
    { Invoke-OfflinePreProvision -Scenario $scenario } | Should -Throw '*target resource group is absent*'
    ($global:maesterOfflineCalls -join '|') | Should -Not -Match 'env set|DELETE'
  }

  It 'accepts a normal empty account inventory and creates a fresh ID' {
    $scenario = New-OfflineScenario
    $scenario.AccountList = @{ value = @() }
    Invoke-OfflinePreProvision -Scenario $scenario
    ($global:maesterOfflineCalls -join '|') | Should -Not -Match 'DELETE|lock delete'
    ($global:maesterOfflineCalls -join '|') | Should -Match 'azd env set AUTOMATION_JOB_SCHEDULE_ID [^|]+ -e test'
  }

  It 'fails closed when an empty account inventory conflicts with a complete or partial prior binding' {
    foreach ($prior in @(
        @{ AUTOMATION_OWNED_ACCOUNT_ID = $script:accountId; AUTOMATION_OWNED_PRINCIPAL_ID = $script:principalId; AUTOMATION_OWNED_JOB_SCHEDULE_ID = $script:scheduleId },
        @{ AUTOMATION_OWNED_ACCOUNT_ID = $script:accountId },
        @{ AUTOMATION_ADOPT_ACCOUNT_ID = $script:accountId; AUTOMATION_ADOPT_PRINCIPAL_ID = $script:principalId; AUTOMATION_ADOPT_JOB_SCHEDULE_ID = $script:scheduleId }
      )) {
      $scenario = New-OfflineScenario
      $scenario.AccountList = @{ value = @() }
      foreach ($key in $prior.Keys) { $scenario.Values[$key] = $prior[$key] }
      { Invoke-OfflinePreProvision -Scenario $scenario } | Should -Throw '*no matching live account*'
      ($global:maesterOfflineCalls -join '|') | Should -Not -Match 'env set|DELETE|lock delete'
    }
  }

  It 'preserves the exact association before a failed ARM redeployment' {
    $scenario = New-OfflineScenario
    $scenario.Values.AUTOMATION_OWNED_ACCOUNT_ID = $script:accountId
    $scenario.Values.AUTOMATION_OWNED_PRINCIPAL_ID = $script:principalId
    $scenario.Values.AUTOMATION_OWNED_JOB_SCHEDULE_ID = $script:scheduleId
    Invoke-OfflinePreProvision -Scenario $scenario
    ($global:maesterOfflineCalls -join '|') | Should -Match "AUTOMATION_JOB_SCHEDULE_ID $($script:scheduleId)"
    ($global:maesterOfflineCalls -join '|') | Should -Not -Match 'DELETE|lock delete'
  }

  It 'fails closed on a mismatched receipt before writing the jobSchedule ID' {
    $scenario = New-OfflineScenario
    $scenario.Values.AUTOMATION_OWNED_ACCOUNT_ID = $script:accountId
    $scenario.Values.AUTOMATION_OWNED_PRINCIPAL_ID = $script:unrelatedId
    $scenario.Values.AUTOMATION_OWNED_JOB_SCHEDULE_ID = $script:scheduleId
    { Invoke-OfflinePreProvision -Scenario $scenario } | Should -Throw '*receipt does not match*'
    ($global:maesterOfflineCalls -join '|') | Should -Not -Match 'env set|DELETE|lock delete'
  }

  It 'rejects paginated or malformed account inventories without writing' {
    $scenario = New-OfflineScenario
    $scenario.AccountList = @{ value = @(); nextLink = 'https://management.azure.com/next' }
    { Invoke-OfflinePreProvision -Scenario $scenario } | Should -Throw '*incomplete*'
    ($global:maesterOfflineCalls -join '|') | Should -Not -Match 'env set|DELETE'
    $scenario.AccountList = @{ value = $null }
    { Invoke-OfflinePreProvision -Scenario $scenario } | Should -Throw '*incomplete*'
    ($global:maesterOfflineCalls -join '|') | Should -Not -Match 'env set|DELETE'
  }

  It 'rejects a paginated jobSchedule inventory before writing' {
    $scenario = New-OfflineScenario
    $scenario.ScheduleList.nextLink = 'https://management.azure.com/next'
    { Invoke-OfflinePreProvision -Scenario $scenario } | Should -Throw '*jobSchedule inventory was incomplete*'
    ($global:maesterOfflineCalls -join '|') | Should -Not -Match 'env set|DELETE'
  }

  It 'does not treat an unreadable group as a fresh deployment' {
    $scenario = New-OfflineScenario -GroupExists 'unknown'
    { Invoke-OfflinePreProvision -Scenario $scenario } | Should -Throw '*Could not verify*'
    ($global:maesterOfflineCalls -join '|') | Should -Not -Match 'env set|DELETE'
  }
}
