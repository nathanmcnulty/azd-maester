Describe 'Maester ACR image target' {
  BeforeAll {
    $buildScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/Build-MaesterImage.ps1'
    $subscriptionId = '11111111-1111-1111-1111-111111111111'
    $resourceGroupName = 'rg-maester-test'
    $deployedJobName = 'caj-maester-verylongen-abc123'
  }

  BeforeEach {
    $global:maesterBuildCalls = 0
    $global:maesterDigest = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    $global:maesterAcrListResponse = '[{"name":"crmaestertest","loginServer":"crmaestertest.azurecr.io","tags":{"environment":"verylongenvironment","managedBy":"azd","workload":"maester","solution":"container-app-job"}}]'
    Mock az {
      $global:LASTEXITCODE = 0
      if ($args[0] -eq 'acr' -and $args[1] -eq 'list') {
        return $global:maesterAcrListResponse
      }
      if ($args[0] -eq 'account' -and $args[1] -eq 'get-access-token') {
        return 'local-test-token'
      }
      if ($args[0] -eq 'acr' -and $args[1] -eq 'build') {
        $global:maesterBuildCalls++
        return
      }
      if ($args[0] -eq 'acr' -and $args[1] -eq 'manifest' -and $args[2] -eq 'show-metadata') {
        return $global:maesterDigest
      }
      throw "Unexpected az command: $($args -join ' ')"
    }
  }

  AfterEach {
    Remove-Variable -Name maesterBuildCalls -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name maesterDigest -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name maesterAcrListResponse -Scope Global -ErrorAction SilentlyContinue
  }

  It 'updates the exact deployed name passed by postprovision' {
    Mock Invoke-RestMethod {
      if ($Method -eq 'GET') {
        return [pscustomobject]@{
          location = 'eastus2'
          tags = @{}
          identity = @{}
          properties = [pscustomobject]@{
            configuration = [pscustomobject]@{ registries = @() }
            template = [pscustomobject]@{ containers = @([pscustomobject]@{ image = 'old-image' }) }
          }
        }
      }
    }

    & $buildScript -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName `
      -EnvironmentName 'verylongenvironment' -ContainerAppJobName $deployedJobName `
      -AcrName 'crmaestertest'

    Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
      $Method -eq 'GET' -and $Uri -like "*/jobs/${deployedJobName}?api-version=*"
    }
    Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
      $Method -eq 'PUT' -and $Uri -like "*/jobs/${deployedJobName}?api-version=*" -and
      $Body -match 'crmaestertest.azurecr.io/maester@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    }
    $global:maesterBuildCalls | Should -Be 1
  }

  It 'does not update the job if ACR cannot resolve a digest' {
    $global:maesterDigest = 'latest'
    Mock Invoke-RestMethod {
      if ($Method -eq 'PUT') { throw 'PUT must not be attempted' }
      [pscustomobject]@{
        location = 'eastus2'; tags = @{}; identity = @{}
        properties = [pscustomobject]@{
          configuration = [pscustomobject]@{ registries = @() }
          template = [pscustomobject]@{ containers = @([pscustomobject]@{ image = 'old-image' }) }
        }
      }
    }
    { & $buildScript -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName -EnvironmentName 'verylongenvironment' -ContainerAppJobName $deployedJobName -AcrName 'crmaestertest' } |
      Should -Throw '*did not return a valid digest*'
    Should -Invoke Invoke-RestMethod -Times 0 -ParameterFilter { $Method -eq 'PUT' }
  }

  It 'discovers the tagged job for direct invocation' {
    Mock Invoke-RestMethod {
      if ($Method -eq 'GET' -and $Uri -like '*/jobs?api-version=*') {
        return [pscustomobject]@{ value = @(
          [pscustomobject]@{ name = 'unrelated-job'; tags = [pscustomobject]@{ environment = 'other'; managedBy = 'azd'; workload = 'maester' } },
          [pscustomobject]@{ name = $deployedJobName; tags = [pscustomobject]@{ environment = 'verylongenvironment'; managedBy = 'azd'; workload = 'maester' } }
        ) }
      }
      return [pscustomobject]@{
        location = 'eastus2'
        tags = @{}
        identity = @{}
        properties = [pscustomobject]@{
          configuration = [pscustomobject]@{ registries = @() }
          template = [pscustomobject]@{ containers = @([pscustomobject]@{ image = 'old-image' }) }
        }
      }
    }

    & $buildScript -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName `
      -EnvironmentName 'verylongenvironment'

    Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
      $Method -eq 'GET' -and $Uri -like "*/jobs/${deployedJobName}?api-version=*"
    }
    $global:maesterBuildCalls | Should -Be 1
  }

  It 'fails before image build when the named job does not exist' {
    Mock Invoke-RestMethod { throw 'not found' }

    {
      & $buildScript -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName `
        -EnvironmentName 'verylongenvironment' -ContainerAppJobName $deployedJobName
    } | Should -Throw "*Failed to read Container App Job '$deployedJobName'*"
    $global:maesterBuildCalls | Should -Be 0
  }

  It 'does not select a sole unrelated job' {
    Mock Invoke-RestMethod {
      return [pscustomobject]@{ value = @(
        [pscustomobject]@{ name = 'unrelated-job' }
      ) }
    }

    {
      & $buildScript -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName `
        -EnvironmentName 'verylongenvironment'
    } | Should -Throw '*Could not identify one Maester Container App Job*'
    $global:maesterBuildCalls | Should -Be 0
    Should -Invoke Invoke-RestMethod -Times 0 -Exactly -ParameterFilter { $Method -eq 'PUT' }
  }

  It 'rejects ambiguous matching jobs before building' {
    Mock Invoke-RestMethod {
      return [pscustomobject]@{ value = @(
        [pscustomobject]@{ name = 'job-one'; tags = [pscustomobject]@{ environment = 'verylongenvironment'; managedBy = 'azd'; workload = 'maester' } },
        [pscustomobject]@{ name = 'job-two'; tags = [pscustomobject]@{ environment = 'verylongenvironment'; managedBy = 'azd'; workload = 'maester' } }
      ) }
    }

    {
      & $buildScript -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName `
        -EnvironmentName 'verylongenvironment'
    } | Should -Throw '*Could not identify one Maester Container App Job*'
    $global:maesterBuildCalls | Should -Be 0
    Should -Invoke Invoke-RestMethod -Times 0 -Exactly -ParameterFilter { $Method -eq 'PUT' }
  }

  It 'rejects a partial job list before building' {
    Mock Invoke-RestMethod {
      return [pscustomobject]@{
        value = @([pscustomobject]@{ name = $deployedJobName; tags = [pscustomobject]@{ environment = 'verylongenvironment'; managedBy = 'azd'; workload = 'maester' } })
        nextLink = 'https://management.azure.com/next-page'
      }
    }

    {
      & $buildScript -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName `
        -EnvironmentName 'verylongenvironment'
    } | Should -Throw '*Container App Job list is incomplete*'
    $global:maesterBuildCalls | Should -Be 0
    Should -Invoke Invoke-RestMethod -Times 0 -Exactly -ParameterFilter { $Method -eq 'PUT' }
  }

  It 'rejects an unrelated singleton registry before building' {
    $global:maesterAcrListResponse = '[{"name":"otherregistry","loginServer":"otherregistry.azurecr.io","tags":{"environment":"other","managedBy":"azd","workload":"maester","solution":"container-app-job"}}]'
    Mock Invoke-RestMethod { throw 'Unexpected ARM request' }

    {
      & $buildScript -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName `
        -EnvironmentName 'verylongenvironment' -ContainerAppJobName $deployedJobName
    } | Should -Throw '*Could not identify one Maester Azure Container Registry*'
    $global:maesterBuildCalls | Should -Be 0
    Should -Invoke Invoke-RestMethod -Times 0 -Exactly
  }

  It 'rejects ambiguous matching registries before building' {
    $global:maesterAcrListResponse = '[{"name":"registryone","loginServer":"registryone.azurecr.io","tags":{"environment":"verylongenvironment","managedBy":"azd","workload":"maester","solution":"container-app-job"}},{"name":"registrytwo","loginServer":"registrytwo.azurecr.io","tags":{"environment":"verylongenvironment","managedBy":"azd","workload":"maester","solution":"container-app-job"}}]'
    Mock Invoke-RestMethod { throw 'Unexpected ARM request' }

    {
      & $buildScript -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName `
        -EnvironmentName 'verylongenvironment' -ContainerAppJobName $deployedJobName
    } | Should -Throw '*Could not identify one Maester Azure Container Registry*'
    $global:maesterBuildCalls | Should -Be 0
    Should -Invoke Invoke-RestMethod -Times 0 -Exactly
  }

  It 'rejects an explicit registry name absent from the selected resource group' {
    Mock Invoke-RestMethod { throw 'Unexpected ARM request' }

    {
      & $buildScript -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName `
        -EnvironmentName 'verylongenvironment' -ContainerAppJobName $deployedJobName `
        -AcrName 'missingregistry'
    } | Should -Throw '*Could not identify one Maester Azure Container Registry*'
    $global:maesterBuildCalls | Should -Be 0
    Should -Invoke Invoke-RestMethod -Times 0 -Exactly
  }
}
