$script:repoRoot = Split-Path -Parent $PSScriptRoot
$automationRoot = Join-Path $script:repoRoot 'automation-account'
$evidenceModule = Join-Path $automationRoot 'scripts\Maester-DeploymentEvidence.psm1'

Import-Module $evidenceModule -Force

Describe 'Automation Account deployment evidence' {
  BeforeEach {
    $script:tenantId = '22222222-2222-2222-2222-222222222222'
    $script:subscriptionId = '11111111-1111-1111-1111-111111111111'
    $script:operationId = '33333333-3333-3333-3333-333333333333'
    $script:resources = @(
      [pscustomobject]@{ type = 'Microsoft.Automation/automationAccounts'; name = 'aa-pilot' },
      [pscustomobject]@{ type = 'Microsoft.Storage/storageAccounts'; name = 'stpilot' }
    )
    $script:validationResult = [pscustomobject]@{
      ValidationPassed = $true
      JobId = '44444444-4444-4444-4444-444444444444'
      FinalStatus = 'Completed'
      CompletedAt = '2026-09-21T12:00:00Z'
    }
  }

  It 'writes schema 1.0 evidence for a direct azd deployment' {
    $result = Write-MaesterDeploymentEvidence `
      -RepositoryRoot $TestDrive `
      -ValidationStartedAt ([datetimeoffset]'2026-09-21T11:59:00Z') `
      -ValidationResult $validationResult `
      -Resources $resources `
      -EnvironmentName pilot `
      -AzureCloud AzureCloud `
      -TenantId $tenantId `
      -SubscriptionId $subscriptionId `
      -ResourceGroupName rg-pilot `
      -AutomationAccountName aa-pilot

    $result.Report.schemaVersion | Should -Be '1.0'
    $result.Report.outcome | Should -Be 'passed'
    $runtimeCheck = $result.Report.checks | Where-Object id -eq 'runtime.runbook-job'
    $runtimeCheck.title | Should -Be 'Maester report lifecycle'
    $runtimeCheck.summary | Should -Match 'Review the Maester report for test outcomes'
    $runtimeCheck.evidence.validationScope | Should -Be 'lifecycle'
    $runtimeCheck.evidence.testOutcomesEvaluated | Should -BeFalse
    $result.Receipt.schemaVersion | Should -Be '1.0'
    $result.Receipt.artifacts | Should -Contain 'reports/deployment-validation.json'
    Test-Path (Join-Path $TestDrive 'reports\deployment-validation.json') | Should -BeTrue
    Test-Path (Join-Path $TestDrive 'reports\deployment-receipt.json') | Should -BeTrue
  }

  It 'binds a GUI receipt to the exact up operation without misbinding validation' {
    $guiEnvironment = @{
      AZD_GUI_PROJECT_ID = 'project-opaque-id'
      AZD_GUI_ENVIRONMENT = 'pilot'
      AZD_GUI_TEMPLATE_ID = 'maester-automation'
      AZD_GUI_SOURCE_REVISION = '0123456789abcdef0123456789abcdef01234567'
      AZD_GUI_CONTRACT_DIGEST = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
      AZD_GUI_OPERATION_ID = $operationId
      AZD_GUI_OPERATION_KIND = 'up'
    }

    $result = Write-MaesterDeploymentEvidence `
      -RepositoryRoot $TestDrive `
      -ValidationStartedAt ([datetimeoffset]'2026-09-21T11:59:00Z') `
      -ValidationResult $validationResult `
      -Resources $resources `
      -EnvironmentName pilot `
      -AzureCloud AzureCloud `
      -TenantId $tenantId `
      -SubscriptionId $subscriptionId `
      -ResourceGroupName rg-pilot `
      -AutomationAccountName aa-pilot `
      -GuiEnvironment $guiEnvironment

    $result.Report.schemaVersion | Should -Be '1.0'
    $result.Receipt.schemaVersion | Should -Be '1.1'
    $management = $result.Receipt.details.azdManagementEvidence
    $management.evidenceClass | Should -Be 'resourceMutation'
    $management.binding.operation.id | Should -Be $operationId
    $management.binding.operation.kind | Should -Be 'up'
    $management.binding.project.environment | Should -Be 'pilot'
    $management.binding.target.subscriptionId | Should -Be $subscriptionId
    $management.binding.source.templateId | Should -Be 'maester-automation'
  }

  It 'rejects a partial GUI context instead of writing weak bound evidence' {
    {
      Get-MaesterGuiReceiptBinding `
        -GuiEnvironment @{ AZD_GUI_PROJECT_ID = 'project-opaque-id' } `
        -EnvironmentName pilot `
        -AzureCloud AzureCloud `
        -TenantId $tenantId `
        -SubscriptionId $subscriptionId `
        -ResourceGroupName rg-pilot
    } | Should -Throw '*incomplete*'
  }

  It 'persists a failed validation report and an actionable receipt' {
    $failed = [pscustomobject]@{
      ValidationPassed = $false
      JobId = '00000000-0000-0000-0000-000000000000'
      FinalStatus = 'Failed'
      CompletedAt = '2026-09-21T12:00:00Z'
    }
    $result = Write-MaesterDeploymentEvidence `
      -RepositoryRoot $TestDrive `
      -ValidationStartedAt ([datetimeoffset]'2026-09-21T11:59:00Z') `
      -ValidationResult $failed `
      -Resources $resources `
      -EnvironmentName pilot `
      -AzureCloud AzureCloud `
      -TenantId $tenantId `
      -SubscriptionId $subscriptionId `
      -ResourceGroupName rg-pilot `
      -AutomationAccountName aa-pilot

    $result.Report.outcome | Should -Be 'failed'
    $result.Receipt.summary.failed | Should -Be 1
    (Get-Content (Join-Path $TestDrive 'reports\deployment-validation.json') -Raw | ConvertFrom-Json).outcome | Should -Be 'failed'
  }
}

Describe 'Vendored module paths' {
  BeforeAll {
    $repoRootForVendorTest = Split-Path -Parent $PSScriptRoot
  }

  It 'resolves every repository-owned vendor reference' {
    $scriptFiles = Get-ChildItem -LiteralPath $repoRootForVendorTest -Recurse -File -Include *.ps1, *.psm1 |
      Where-Object { $_.FullName -notmatch '[\\/](?:\.git|tests)[\\/]' }
    $broken = @()
    foreach ($file in $scriptFiles) {
      foreach ($match in Select-String -LiteralPath $file.FullName -Pattern 'Join-Path \$PSScriptRoot ''(?<path>vendor\\[^'']+)''' -AllMatches) {
        foreach ($item in $match.Matches) {
          $target = Join-Path (Split-Path -Parent $file.FullName) $item.Groups['path'].Value
          if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
            $broken += "$($file.FullName): $target"
          }
        }
      }
    }
    $broken | Should -BeNullOrEmpty
  }
}
