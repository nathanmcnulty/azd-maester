Describe 'Maester Azure DevOps cleanup' {
  BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $cleanupPath = Join-Path $repoRoot 'azure-devops/scripts/vendor/Azd.MaesterHooks/Maester-PreDownCleanup.psm1'
    $cleanup = Get-Content -LiteralPath $cleanupPath -Raw
  }

  It 'reissues service-connection deletion while Azure DevOps state converges' {
    $cleanup | Should -Match '\$maxDeleteAttempts\s*=\s*6'
    $cleanup | Should -Match '\$retryDelaySeconds\s*=\s*5'
    $cleanup | Should -Match '(?s)for \(\$attempt = 1; \$attempt -le \$maxDeleteAttempts; \$attempt\+\+\).*?Invoke-AdoRest.*?-Method DELETE.*?Invoke-AdoRest.*?-Method GET'
    $cleanup | Should -Match 'Reissue DELETE'
  }

  It 'supports subscription-scoped Azure CLI access tokens' {
    $helpersPath = Join-Path $repoRoot 'azure-devops/scripts/vendor/Azd.MaesterHooks/Maester-SetupHelpers.psm1'
    $helpers = Get-Content -LiteralPath $helpersPath -Raw

    $helpers | Should -Match '\[string\]\$SubscriptionId'
    $helpers | Should -Match 'tokenArgs\s*\+=\s*@\(.+--subscription.+\$SubscriptionId'
    $helpers | Should -Match '(?s)if \([^\r\n]*SubscriptionId[^\r\n]*\).*?--subscription.*?elseif \([^\r\n]*TenantId[^\r\n]*\).*?--tenant'
  }
}

Describe 'Maester Web App security group wizard validation' {
  BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $wizardPath = Join-Path $repoRoot 'azure-devops/scripts/vendor/Azd.MaesterHooks/Maester-UpWizard.psm1'
    Import-Module $wizardPath -Force
  }

  AfterAll {
    Remove-Module Maester-UpWizard -Force -ErrorAction SilentlyContinue
  }

  It 'rejects a <case> cached group ID before any environment value is persisted' -TestCases @(
    @{ case = 'blank'; key = 'SECURITY_GROUP_OBJECT_ID'; value = '' }
    @{ case = 'malformed'; key = 'SECURITY_GROUP_OBJECT_ID'; value = 'not-a-guid' }
    @{ case = 'nil'; key = 'SECURITY_GROUP_OBJECT_ID'; value = '00000000-0000-0000-0000-000000000000' }
    @{ case = 'malformed legacy fallback'; key = 'EASY_AUTH_SECURITY_GROUP_OBJECT_ID'; value = 'not-a-guid' }
  ) {
    param($key, $value)

    InModuleScope Maester-UpWizard -Parameters @{ cachedKey = $key; cachedGroupId = $value } {
      Mock Test-InteractiveWizard { $false }
      Mock Get-AzdEnvironmentValues {
        $values = @{
          INCLUDE_WEB_APP = 'true'
          INCLUDE_EXCHANGE = 'false'
          INCLUDE_TEAMS = 'false'
          INCLUDE_AZURE = 'false'
        }
        $values[$cachedKey] = $cachedGroupId
        $values
      }
      Mock Set-AzdEnvValueStrict {}

      {
        Invoke-MaesterUpWizard `
          -SolutionName automation-account `
          -SubscriptionId '11111111-1111-4111-8111-111111111111'
      } | Should -Throw '*SECURITY_GROUP_OBJECT_ID must be a non-empty GUID when INCLUDE_WEB_APP=true*INCLUDE_WEB_APP=false*'

      Should -Invoke Set-AzdEnvValueStrict -Times 0 -Exactly
    }
  }

  It 'normalizes a valid cached group ID and persists it only after validation' {
    InModuleScope Maester-UpWizard {
      Mock Test-InteractiveWizard { $false }
      Mock Get-AzdEnvironmentValues {
        @{
          INCLUDE_WEB_APP = 'true'
          INCLUDE_EXCHANGE = 'false'
          INCLUDE_TEAMS = 'false'
          INCLUDE_AZURE = 'false'
          SECURITY_GROUP_OBJECT_ID = '{AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE}'
        }
      }
      Mock Set-AzdEnvValueStrict {}

      Invoke-MaesterUpWizard `
        -SolutionName automation-account `
        -SubscriptionId '11111111-1111-4111-8111-111111111111'

      Should -Invoke Set-AzdEnvValueStrict -Times 1 -Exactly -ParameterFilter {
        $Name -eq 'SECURITY_GROUP_OBJECT_ID' -and $Value -ceq 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
      }
    }
  }

  It 'reprompts after an invalid interactive value and returns the normalized group ID' {
    InModuleScope Maester-UpWizard {
      $responses = [Collections.Generic.Queue[string]]::new()
      $responses.Enqueue('still-not-a-guid')
      $responses.Enqueue('{AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE}')
      Mock Read-Host { $responses.Dequeue() }
      Mock Write-Host {}

      $result = Read-SecurityGroupObjectId -CurrentValue 'invalid-cached-value' -InteractiveWizard $true

      $result | Should -BeExactly 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
      Should -Invoke Read-Host -Times 2 -Exactly
      Should -Invoke Write-Host -ParameterFilter {
        [string]$Object -match 'Microsoft Entra ID > Groups > All groups' -and
        [string]$Object -match 'choose No for Include Web App'
      }
    }
  }

  It 'keeps the disabled Web App baseline without validating, persisting, or looking up a group' {
    InModuleScope Maester-UpWizard {
      Mock Test-InteractiveWizard { $false }
      Mock Get-AzdEnvironmentValues {
        @{
          INCLUDE_WEB_APP = 'false'
          INCLUDE_EXCHANGE = 'false'
          INCLUDE_TEAMS = 'false'
          INCLUDE_AZURE = 'false'
          SECURITY_GROUP_OBJECT_ID = 'invalid-but-disabled'
        }
      }
      Mock Set-AzdEnvValueStrict {}
      Mock Invoke-RestMethod { throw 'A disabled Web App must not invoke Graph.' }

      {
        Invoke-MaesterUpWizard `
          -SolutionName automation-account `
          -SubscriptionId '11111111-1111-4111-8111-111111111111'
      } | Should -Not -Throw

      Should -Invoke Set-AzdEnvValueStrict -Times 0 -Exactly -ParameterFilter {
        $Name -eq 'SECURITY_GROUP_OBJECT_ID'
      }
      Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }
  }
}

Describe 'Legacy hook upgrade preserves unproven Azure DevOps repository ownership' {
  BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'azure-devops/scripts/vendor/Azd.MaesterHooks/Maester-PreDownCleanup.psm1') -Force
  }
  AfterAll { Remove-Module Maester-PreDownCleanup -Force -ErrorAction SilentlyContinue }

  It 'keeps the legacy repository when no creation flag was recorded' {
    InModuleScope Maester-PreDownCleanup {
      Mock Get-AzdEnvironmentValues {
        @{
          AZURE_SUBSCRIPTION_ID = '11111111-1111-4111-8111-111111111111'
          AZDO_ORGANIZATION = 'example-org'
          AZDO_PROJECT = 'example-project'
          AZDO_REPOSITORY = 'existing-repository'
          AZDO_REPOSITORY_ID = 'repository-id'
        }
      }
      Mock az { $global:LASTEXITCODE = 0 }
      Mock Remove-TrackedDirectoryRoleAssignments {}
      Mock Remove-TrackedAzureRoleAssignments {}
      Mock Remove-TrackedBaseRoleAssignments {}
      Mock Remove-TrackedExchangeAppRoleAssignments {}
      Mock Invoke-AdoRest { [pscustomobject]@{ id = 'project-id' } }
      Mock Write-Host {}
      Mock Write-Warning { throw "Unexpected cleanup failure: $Message" }

      Invoke-MaesterAzureDevOpsPreDownCleanup

      Should -Invoke Invoke-AdoRest -Times 0 -Exactly -ParameterFilter { $Method -eq 'DELETE' }
      Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { $Object -like 'Preserving Azure DevOps repository*' }
    }
  }
}
