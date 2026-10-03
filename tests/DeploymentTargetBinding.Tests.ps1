BeforeAll {
  $repoRoot = Split-Path $PSScriptRoot -Parent
  $variants = @('automation-account', 'container-app-job', 'azure-devops', 'function-app')
  $subscriptionId = '43babb60-9e73-4dc8-b769-4401c01aad73'
  $resourceGroupName = 'rg-maester-test'
  $environmentName = 'test'

  function New-TestResource {
    param([string]$Name, [string]$Type, [string]$Solution, [string]$Kind = '')
    [pscustomobject]@{
      name = $Name
      type = $Type
      id = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/$Type/$Name"
      kind = $Kind
      tags = [pscustomobject]@{ workload = 'maester'; solution = $Solution; environment = $environmentName; managedBy = 'azd' }
    }
  }
}

Describe 'Exact nested deployment target binding' {
  It 'selects only the explicit Function App among multiple sites and rejects wrong or ambiguous identities' {
    Import-Module (Join-Path $repoRoot 'function-app/scripts/Resolve-DeploymentTarget.psm1') -Force
    $owned = New-TestResource -Name 'func-maester-exact' -Type 'Microsoft.Web/sites' -Solution 'function-app' -Kind 'functionapp,linux'
    $unrelated = New-TestResource -Name 'func-other' -Type 'Microsoft.Web/sites' -Solution 'other' -Kind 'functionapp,linux'
    $payload = [pscustomobject]@{ value = @($unrelated, $owned) }
    $params = @{ Payload = $payload; Name = $owned.name; ProviderType = 'Microsoft.Web/sites';
      SubscriptionId = $subscriptionId; ResourceGroupName = $resourceGroupName;
      EnvironmentName = $environmentName; SolutionName = 'function-app'; Kind = 'FunctionApp' }
    (Select-ExactMaesterResource @params).id | Should -Be $owned.id
    { Select-ExactMaesterResource @params -Name 'func-missing' } | Should -Throw
    $payload.value = @($owned, $owned)
    { Select-ExactMaesterResource @params } | Should -Throw
    $payload.value = @($unrelated, $owned)
    $owned.id = '/subscriptions/other/resourceGroups/rg-maester-test/providers/Microsoft.Web/sites/func-maester-exact'
    { Select-ExactMaesterResource @params } | Should -Throw
  }

  It 'reports only plans linked to the exact Function and optional Web App in a mixed resource group' {
    Import-Module (Join-Path $repoRoot 'function-app/scripts/Resolve-DeploymentTarget.psm1') -Force
    $unrelatedPlan = New-TestResource -Name 'plan-unrelated' -Type 'Microsoft.Web/serverfarms' -Solution 'other'
    $functionPlan = New-TestResource -Name 'plan-function-exact' -Type 'Microsoft.Web/serverfarms' -Solution 'function-app'
    $webPlan = New-TestResource -Name 'asp-web-exact' -Type 'Microsoft.Web/serverfarms' -Solution 'function-app'
    $payload = [pscustomobject]@{ value = @($unrelatedPlan, $functionPlan, $webPlan) }
    $functionSite = [pscustomobject]@{ name = 'func-exact'; properties = [pscustomobject]@{ serverFarmId = $functionPlan.id } }
    $webSite = [pscustomobject]@{ name = 'web-exact'; properties = [pscustomobject]@{ serverFarmId = $webPlan.id } }
    $scope = @{ Payload = $payload; SubscriptionId = $subscriptionId; ResourceGroupName = $resourceGroupName;
      EnvironmentName = $environmentName }
    (Select-MaesterLinkedPlan @scope -Site $functionSite).id | Should -Be $functionPlan.id
    (Select-MaesterLinkedPlan @scope -Site $webSite).id | Should -Be $webPlan.id
    $functionSite.properties.serverFarmId = $unrelatedPlan.id
    { Select-MaesterLinkedPlan @scope -Site $functionSite } | Should -Throw
    $functionSite.properties.serverFarmId = '/subscriptions/other/resourceGroups/rg-maester-test/providers/Microsoft.Web/serverfarms/plan-function-exact'
    { Select-MaesterLinkedPlan @scope -Site $functionSite } | Should -Throw
    $functionSite.properties.serverFarmId = $functionPlan.id
    $payload.value = @($unrelatedPlan, $functionPlan, $functionPlan, $webPlan)
    { Select-MaesterLinkedPlan @scope -Site $functionSite } | Should -Throw

    $summary = Get-Content -LiteralPath (Join-Path $repoRoot 'function-app/scripts/Run-AzdPostProvision.ps1') -Raw
    $summary | Should -Not -Match "name -like '(plan|asp)-\*'"
    $summary | Should -Match 'Select-MaesterLinkedPlan -Payload \$resourcesPayload -Site \$functionAppDetails'
    $summary | Should -Match 'Select-MaesterLinkedPlan -Payload \$resourcesPayload -Site \$webAppDetails'
    $summary | Should -Match '(?s)\$webAppPlanResource = \$null.*if \(\$webAppEnabledFromDeployment -eq ''true''\).*\$webAppPlanResource = Select-MaesterLinkedPlan'
  }

  It 'rejects unrelated singleton, wrong type, and incomplete inventory in every independent variant' -ForEach @('automation-account', 'container-app-job', 'azure-devops', 'function-app') {
    $variant = $_
    Import-Module (Join-Path $repoRoot "$variant/scripts/Resolve-DeploymentTarget.psm1") -Force
    $unrelated = New-TestResource -Name 'stunrelated' -Type 'Microsoft.Storage/storageAccounts' -Solution 'other'
    $owned = New-TestResource -Name 'stmaesterexact' -Type 'Microsoft.Storage/storageAccounts' -Solution $variant
    $payload = [pscustomobject]@{ value = @($unrelated, $owned) }
    $params = @{ Payload = $payload; Name = $owned.name; ProviderType = 'Microsoft.Storage/storageAccounts';
      SubscriptionId = $subscriptionId; ResourceGroupName = $resourceGroupName;
      EnvironmentName = $environmentName; SolutionName = $variant }
    (Select-ExactMaesterResource @params).id | Should -Be $owned.id
    $payload.value = @($unrelated)
    { Select-ExactMaesterResource @params } | Should -Throw
    $payload.value = @($unrelated, $owned)
    $owned.type = 'Microsoft.Web/sites'
    { Select-ExactMaesterResource @params } | Should -Throw
    $owned.type = 'Microsoft.Storage/storageAccounts'
    $payload | Add-Member -NotePropertyName nextLink -NotePropertyValue 'https://management.azure.com/next'
    { Select-ExactMaesterResource @params } | Should -Throw
  }

  It 'binds optional Web App only to the expected tagged site and rejects function-kind sites' -ForEach @('automation-account', 'container-app-job', 'azure-devops', 'function-app') {
    $variant = $_
    Import-Module (Join-Path $repoRoot "$variant/scripts/Resolve-DeploymentTarget.psm1") -Force
    $owned = New-TestResource -Name 'app-maester-exact' -Type 'Microsoft.Web/sites' -Solution $variant -Kind 'app,linux'
    $unrelated = New-TestResource -Name 'app-other' -Type 'Microsoft.Web/sites' -Solution 'other' -Kind 'app,linux'
    $payload = [pscustomobject]@{ value = @($unrelated, $owned) }
    $params = @{ Payload = $payload; Name = $owned.name; ProviderType = 'Microsoft.Web/sites';
      SubscriptionId = $subscriptionId; ResourceGroupName = $resourceGroupName;
      EnvironmentName = $environmentName; SolutionName = $variant; Kind = 'WebApp' }
    (Select-ExactMaesterResource @params).id | Should -Be $owned.id
    $owned.kind = 'functionapp,linux'
    { Select-ExactMaesterResource @params } | Should -Throw
  }

  It 'rejects duplicate or paged Graph application lookup before caller can mutate it' -ForEach @('automation-account', 'container-app-job', 'azure-devops', 'function-app') {
    Import-Module (Join-Path $repoRoot "$_/scripts/Resolve-DeploymentTarget.psm1") -Force
    $app = [pscustomobject]@{ id = 'object-1'; appId = 'client-1'; displayName = 'maester-easyauth-exact' }
    (Select-UniqueGraphApplication -Response ([pscustomobject]@{ value = @($app) }) -ExpectedValue $app.displayName).id | Should -Be $app.id
    { Select-UniqueGraphApplication -Response ([pscustomobject]@{ value = @($app, $app) }) -ExpectedValue $app.displayName } | Should -Throw
    { Select-UniqueGraphApplication -Response ([pscustomobject]@{ value = @($app); '@odata.nextLink' = 'next' }) -ExpectedValue $app.displayName } | Should -Throw
    { Select-UniqueGraphApplication -Response ([pscustomobject]@{ value = @($app) }) -ExpectedValue 'different' } | Should -Throw
    (Select-UniqueGraphApplication -Response ([pscustomobject]@{ value = @() }) -ExpectedValue $app.displayName) | Should -BeNullOrEmpty
    { Select-UniqueGraphApplication -Response ([pscustomobject]@{ value = $null }) -ExpectedValue $app.displayName } | Should -Throw
    { Select-UniqueGraphApplication -Response ([pscustomobject]@{}) -ExpectedValue $app.displayName } | Should -Throw
    { Select-UniqueGraphApplication -Response ([pscustomobject]@{ value = 'not an array' }) -ExpectedValue $app.displayName } | Should -Throw
    { Select-UniqueGraphApplication -Response ([pscustomobject]@{ value = [pscustomobject]@{} }) -ExpectedValue $app.displayName } | Should -Throw
  }

  It 'reads and writes only the selected azd environment and rejects scope mismatch' -ForEach @('automation-account', 'container-app-job', 'azure-devops', 'function-app') {
    $variant = $_
    Import-Module (Join-Path $repoRoot "$variant/scripts/Resolve-DeploymentTarget.psm1") -Force
    $global:maesterAzdArgs = [System.Collections.Generic.List[string]]::new()
    $global:maesterAzdDefaultEnv = 'B'
    $global:maesterAzdNamedMismatch = $false
    $savedStorageOutput = $env:STORAGE_ACCOUNT_NAME
    $savedWebEnabledOutput = $env:WEB_APP_ENABLED
    $env:STORAGE_ACCOUNT_NAME = 'stale-process-storage'
    $env:WEB_APP_ENABLED = 'false'
    function global:azd {
      $global:maesterAzdArgs.Add(($args -join ' '))
      $global:LASTEXITCODE = 0
      if ($args[0] -eq 'env' -and $args[1] -eq 'get-values') {
        if ($args -contains '-e' -and $global:maesterAzdNamedMismatch) {
          return '{"AZURE_ENV_NAME":"A","AZURE_SUBSCRIPTION_ID":"sub-B","AZURE_RESOURCE_GROUP":"rg-B"}'
        }
        if ($args -contains '-e') {
          return '{"AZURE_ENV_NAME":"B","AZURE_SUBSCRIPTION_ID":"sub-B","AZURE_RESOURCE_GROUP":"rg-B","STORAGE_ACCOUNT_NAME":"selected-storage","WEB_APP_ENABLED":"true","WEB_APP_NAME":"selected-web","FUNCTION_APP_NAME":"selected-function","containerAppJobName":"selected-job","acrName":"selected-acr"}'
        }
        return ('{{"AZURE_ENV_NAME":"{0}","AZURE_SUBSCRIPTION_ID":"sub-B","AZURE_RESOURCE_GROUP":"rg-B"}}' -f $global:maesterAzdDefaultEnv)
      }
    }
    try {
      $params = @{ EnvironmentName = 'B'; SubscriptionId = 'sub-B'; ResourceGroupName = 'rg-B'; ProjectRoot = $repoRoot }
      $values = Assert-MaesterAzdTarget @params
      $values['STORAGE_ACCOUNT_NAME'] | Should -Be 'selected-storage'
      $values['WEB_APP_ENABLED'] | Should -Be 'true'
      $values['WEB_APP_NAME'] | Should -Be 'selected-web'
      $tags = [pscustomobject]@{ workload = 'maester'; solution = $variant; environment = 'B'; managedBy = 'azd' }
      $selectedStorage = [pscustomobject]@{ name = 'selected-storage'; type = 'Microsoft.Storage/storageAccounts';
        id = '/subscriptions/sub-B/resourceGroups/rg-B/providers/Microsoft.Storage/storageAccounts/selected-storage'; tags = $tags }
      $staleStorage = [pscustomobject]@{ name = 'stale-process-storage'; type = 'Microsoft.Storage/storageAccounts';
        id = '/subscriptions/sub-B/resourceGroups/rg-B/providers/Microsoft.Storage/storageAccounts/stale-process-storage'; tags = $tags }
      $storage = Select-ExactMaesterResource -Payload ([pscustomobject]@{ value = @($staleStorage, $selectedStorage) }) `
        -Name ([string]$values['STORAGE_ACCOUNT_NAME']) -ProviderType 'Microsoft.Storage/storageAccounts' `
        -SubscriptionId sub-B -ResourceGroupName rg-B -EnvironmentName B -SolutionName $variant
      $storage.name | Should -Be 'selected-storage'
      $selectedWeb = [pscustomobject]@{ name = 'selected-web'; type = 'Microsoft.Web/sites'; kind = 'app,linux';
        id = '/subscriptions/sub-B/resourceGroups/rg-B/providers/Microsoft.Web/sites/selected-web'; tags = $tags }
      if ([string]$values['WEB_APP_ENABLED'] -eq 'true') {
        (Select-ExactMaesterResource -Payload ([pscustomobject]@{ value = @($selectedWeb) }) `
          -Name ([string]$values['WEB_APP_NAME']) -ProviderType 'Microsoft.Web/sites' -Kind WebApp `
          -SubscriptionId sub-B -ResourceGroupName rg-B -EnvironmentName B -SolutionName $variant).name | Should -Be 'selected-web'
      }
      @($global:maesterAzdArgs | Where-Object { $_ -like 'env set*' }).Count | Should -Be 0
      Set-MaesterAzdValue -EnvironmentName B -ProjectRoot $repoRoot -Name 'RECEIPT' -Value 'ok'
      $global:maesterAzdArgs[0] | Should -Match 'env get-values --output json --cwd'
      $global:maesterAzdArgs[1] | Should -Match 'env get-values --output json -e B --cwd'
      $global:maesterAzdArgs[2] | Should -Match 'env set RECEIPT ok -e B --cwd'
      $global:maesterAzdDefaultEnv = 'A'
      { Assert-MaesterAzdTarget @params } | Should -Throw
      $global:maesterAzdDefaultEnv = 'B'
      $global:maesterAzdNamedMismatch = $true
      { Assert-MaesterAzdTarget @params } | Should -Throw
      @($global:maesterAzdArgs | Where-Object { $_ -like 'env set*' }).Count | Should -Be 1
    }
    finally {
      $env:STORAGE_ACCOUNT_NAME = $savedStorageOutput
      $env:WEB_APP_ENABLED = $savedWebEnabledOutput
      Remove-Item function:azd -ErrorAction SilentlyContinue
      Remove-Variable maesterAzdArgs, maesterAzdDefaultEnv, maesterAzdNamedMismatch -Scope Global -ErrorAction SilentlyContinue
    }
  }

  It 'blocks the pinned Automation wizard when the default azd environment differs and binds its schedule receipt' {
    $hook = Join-Path $repoRoot 'automation-account/scripts/Run-AzdPreProvision.ps1'
    $saved = @{}
    foreach ($name in @('AZURE_ENV_NAME', 'AZURE_SUBSCRIPTION_ID', 'AZURE_LOCATION', 'AZURE_RESOURCE_GROUP', 'automationAccountName')) {
      $saved[$name] = [Environment]::GetEnvironmentVariable($name)
    }
    $global:maesterPreprovEnv = 'A'
    $global:maesterWizardSwitchEnv = $false
    $global:maesterPreprovCalls = [System.Collections.Generic.List[string]]::new()
    function global:azd {
      $global:maesterPreprovCalls.Add(($args -join ' '))
      $global:LASTEXITCODE = 0
      if ($args[1] -eq 'get-values') {
        return ('{{"AZURE_ENV_NAME":"{0}","AZURE_SUBSCRIPTION_ID":"sub-B"}}' -f $global:maesterPreprovEnv)
      }
    }
    function global:az { $global:LASTEXITCODE = 0; return '[]' }
    function global:Import-Module {
      if ([string]$args[0] -like '*Resolve-DeploymentTarget.psm1') {
        Microsoft.PowerShell.Core\Import-Module $args[0] -Force
      }
    }
    function global:Invoke-MaesterPreProvision {
      $global:maesterPreprovCalls.Add('wizard')
      if ($global:maesterWizardSwitchEnv) { $global:maesterPreprovEnv = 'A' }
    }
    try {
      $env:AZURE_ENV_NAME = 'B'
      $env:AZURE_SUBSCRIPTION_ID = 'sub-B'
      $env:AZURE_LOCATION = 'eastus'
      $env:AZURE_RESOURCE_GROUP = 'rg-B'
      $env:automationAccountName = ''
      { & $hook -SubscriptionId 'sub-B' -EnvironmentName 'B' } | Should -Throw
      @($global:maesterPreprovCalls | Where-Object { $_ -eq 'wizard' -or $_ -like 'env set*' }).Count | Should -Be 0
      $global:maesterPreprovEnv = 'B'
      & $hook -SubscriptionId 'sub-B' -EnvironmentName 'B'
      $global:maesterPreprovCalls | Should -Contain 'wizard'
      @($global:maesterPreprovCalls | Where-Object { $_ -match '^env set AUTOMATION_JOB_SCHEDULE_ID [^ ]+ -e B --cwd ' }).Count | Should -Be 1
      $global:maesterWizardSwitchEnv = $true
      { & $hook -SubscriptionId 'sub-B' -EnvironmentName 'B' } | Should -Throw
      @($global:maesterPreprovCalls | Where-Object { $_ -like 'env set*' }).Count | Should -Be 1
    }
    finally {
      foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
      foreach ($name in @('azd', 'az', 'Import-Module', 'Invoke-MaesterPreProvision')) {
        Remove-Item "function:$name" -ErrorAction SilentlyContinue
      }
      Remove-Variable maesterPreprovEnv, maesterPreprovCalls, maesterWizardSwitchEnv -Scope Global -ErrorAction SilentlyContinue
    }
  }

  It 'blocks each other pinned preprovision wizard when the current azd selection differs' -ForEach @('container-app-job', 'azure-devops', 'function-app') {
    $hook = Join-Path $repoRoot "$_/scripts/Run-AzdPreProvision.ps1"
    $savedName = $env:AZURE_ENV_NAME
    $savedSubscription = $env:AZURE_SUBSCRIPTION_ID
    $savedTenant = $env:AZURE_TENANT_ID
    $global:maesterPreprovEnv = 'A'
    $global:maesterWizardCalls = 0
    function global:azd {
      $global:LASTEXITCODE = 0
      return ('{{"AZURE_ENV_NAME":"{0}","AZURE_SUBSCRIPTION_ID":"sub-B","AZURE_TENANT_ID":"tenant-B"}}' -f $global:maesterPreprovEnv)
    }
    function global:Import-Module {
      if ([string]$args[0] -like '*Resolve-DeploymentTarget.psm1') {
        Microsoft.PowerShell.Core\Import-Module $args[0] -Force
      }
    }
    function global:Invoke-MaesterPreProvision { $global:maesterWizardCalls++ }
    try {
      $env:AZURE_ENV_NAME = 'B'
      $env:AZURE_SUBSCRIPTION_ID = 'sub-B'
      $env:AZURE_TENANT_ID = 'tenant-B'
      { & $hook -SubscriptionId 'sub-B' -TenantId 'tenant-B' -EnvironmentName 'B' } | Should -Throw
      $global:maesterWizardCalls | Should -Be 0
      $global:maesterPreprovEnv = 'B'
      & $hook -SubscriptionId 'sub-B' -TenantId 'tenant-B' -EnvironmentName 'B'
      $global:maesterWizardCalls | Should -Be 1
    }
    finally {
      $env:AZURE_ENV_NAME = $savedName
      $env:AZURE_SUBSCRIPTION_ID = $savedSubscription
      $env:AZURE_TENANT_ID = $savedTenant
      foreach ($name in @('azd', 'Import-Module', 'Invoke-MaesterPreProvision')) {
        Remove-Item "function:$name" -ErrorAction SilentlyContinue
      }
      Remove-Variable maesterPreprovEnv, maesterWizardCalls -Scope Global -ErrorAction SilentlyContinue
    }
  }

  It 'verifies the exact Automation association before PUT and records ownership only after GET' {
    $preprovision = Get-Content -LiteralPath (Join-Path $repoRoot 'automation-account/scripts/Run-AzdPreProvision.ps1') -Raw
    $setup = Get-Content -LiteralPath (Join-Path $repoRoot 'automation-account/scripts/Setup-PostDeploy.ps1') -Raw
    $preprovision | Should -Not -Match '(?i)az\s+(rest\s+--method\s+DELETE|lock\s+delete)'
    $beforeWrite = $setup.IndexOf('Assert-MaesterJobScheduleWriteTarget', [StringComparison]::Ordinal)
    $put = $setup.IndexOf('Invoke-RestMethod -Method PUT -Uri "https://management.azure.com$jobScheduleUri"', [StringComparison]::Ordinal)
    $afterWrite = $setup.IndexOf('Assert-MaesterOwnershipReceiptTarget', [StringComparison]::Ordinal)
    $receipt = $setup.IndexOf("Set-AzdEnvValue -Name 'AUTOMATION_OWNED_ACCOUNT_ID'", [StringComparison]::Ordinal)
    $beforeWrite | Should -BeGreaterThan -1
    $put | Should -BeGreaterThan $beforeWrite
    $afterWrite | Should -BeGreaterThan $put
    $receipt | Should -BeGreaterThan $afterWrite
  }

  It 'wires exact output contracts before optional Web App setup in all four modes' -ForEach @('automation-account', 'container-app-job', 'azure-devops', 'function-app') {
    $variant = $_
    $bicep = Get-Content -LiteralPath (Join-Path $repoRoot "$variant/infra/main.bicep") -Raw
    $setup = Get-Content -LiteralPath (Join-Path $repoRoot "$variant/scripts/Setup-PostDeploy.ps1") -Raw
    foreach ($name in @('STORAGE_ACCOUNT_NAME', 'WEB_APP_NAME', 'WEB_APP_ENABLED')) {
      $bicep | Should -Match "output $name string"
    }
    $setup | Should -Match "Select-ExactMaesterResource -Payload .* -Name \(\[string\]\`$deploymentValues\['STORAGE_ACCOUNT_NAME'\]\)"
    $setup | Should -Match "\[string\]\`$deploymentValues\['WEB_APP_ENABLED'\] -eq 'true'"
    $setup | Should -Not -Match 'preferredWebAppName|preferredStorageAccountName'
    $setup | Should -Match 'Assert-MaesterAzdTarget -EnvironmentName \$EnvironmentName'
    $setup | Should -Match 'Set-MaesterAzdValue -EnvironmentName \$EnvironmentName'
    $setup | Should -Not -Match '(?m)^\s*&\s*azd env set '
    $setup | Should -Match "Set-AzdEnvValue -Name 'EASY_AUTH_ENTRA_APP_OBJECT_ID'"
    $setup | Should -Not -Match '\$env:(STORAGE_ACCOUNT_NAME|WEB_APP_ENABLED|WEB_APP_NAME|FUNCTION_APP_NAME|ACR_NAME)'
    foreach ($name in @('STORAGE_ACCOUNT_NAME', 'WEB_APP_ENABLED', 'WEB_APP_NAME')) {
      $setup | Should -Match "\`$deploymentValues\['$name'\]"
    }
    $storageBinding = $setup.IndexOf("-Name ([string]`$deploymentValues['STORAGE_ACCOUNT_NAME'])", [StringComparison]::Ordinal)
    $firstReceiptWrite = $setup.IndexOf("`nSet-AzdEnvValue -Name ", [StringComparison]::Ordinal)
    $storageBinding | Should -BeGreaterThan -1
    $firstReceiptWrite | Should -BeGreaterThan $storageBinding
    $run = Get-Content -LiteralPath (Join-Path $repoRoot "$variant/scripts/Run-AzdPostProvision.ps1") -Raw
    $run | Should -Match 'azd env get-values --output json -e \$EnvironmentName --cwd \$projectRoot'
    if ($variant -in @('automation-account', 'container-app-job')) {
      $run | Should -Match "\`$envValues\['WEB_APP_ENABLED'\] -eq 'true'"
      $run | Should -Match 'Select-ExactMaesterResource -Payload \$resourcesPayload'
      $run | Should -Not -Match 'Where-Object \{ \$_\.type -eq ''Microsoft.Web/sites'' \} \| Select-Object -First 1'
    }
    $webBinding = $setup.IndexOf("-Name ([string]`$deploymentValues['WEB_APP_NAME'])", [StringComparison]::Ordinal)
    $webMutation = $setup.IndexOf('$easyAuthDisplayName =', [StringComparison]::Ordinal)
    $webBinding | Should -BeGreaterThan -1
    $webMutation | Should -BeGreaterThan $webBinding
    if ($variant -eq 'azure-devops') {
      $setup.IndexOf('$websiteContributorRoleId =', [StringComparison]::Ordinal) | Should -BeGreaterThan $webBinding
      $setup.IndexOf('Connect-ADOPS -Organization', [StringComparison]::Ordinal) | Should -BeGreaterThan $webBinding
      $setup | Should -Match 'Select-UniqueGraphApplication -Response \$existingAppsResponse'
    }
    if ($variant -eq 'function-app') {
      $bicep | Should -Match 'output FUNCTION_APP_NAME string'
      $bicep | Should -Match 'output functionAppPrincipalId string'
      $setup | Should -Match "Select-ExactMaesterResource -Payload .* -Name \(\[string\]\`$deploymentValues\['FUNCTION_APP_NAME'\]\)"
      $setup.IndexOf("-Name ([string]`$deploymentValues['FUNCTION_APP_NAME'])", [StringComparison]::Ordinal) |
        Should -BeLessThan $setup.IndexOf('Grant-MaesterGraphPermissions.ps1', [StringComparison]::Ordinal)
      $setup.IndexOf("`$principalId -ine [string]`$deploymentValues['functionAppPrincipalId']", [StringComparison]::Ordinal) |
        Should -BeLessThan $firstReceiptWrite
    }
    if ($variant -eq 'automation-account') {
      $bicep | Should -Match 'output automationPrincipalId string'
      $setup | Should -Match "Select-ExactMaesterResource -Payload \`$automationPayload -Name \`$preferredAutomationAccountName"
      $setup.IndexOf('-Payload $automationPayload', [StringComparison]::Ordinal) |
        Should -BeLessThan $setup.IndexOf('Grant-MaesterGraphPermissions.ps1', [StringComparison]::Ordinal)
      $setup.IndexOf('-Payload $automationPayload', [StringComparison]::Ordinal) |
        Should -BeLessThan $setup.IndexOf('$readerAssignmentPath =', [StringComparison]::Ordinal)
      $setup.IndexOf("`$principalId -ine [string]`$deploymentValues['automationPrincipalId']", [StringComparison]::Ordinal) |
        Should -BeLessThan $setup.IndexOf('$readerAssignmentPath =', [StringComparison]::Ordinal)
    }
    if ($variant -eq 'container-app-job') {
      $bicep | Should -Match 'output containerAppJobPrincipalId string'
      $setup.IndexOf('-Payload $jobsPayload', [StringComparison]::Ordinal) |
        Should -BeLessThan $setup.IndexOf('$readerAssignmentPath =', [StringComparison]::Ordinal)
      $setup | Should -Match "\`$deploymentValues\['containerAppJobName'\]"
      $setup | Should -Match "\`$deploymentValues\['acrName'\]"
      $setup.IndexOf("`$principalId -ine [string]`$deploymentValues['containerAppJobPrincipalId']", [StringComparison]::Ordinal) |
        Should -BeLessThan $setup.IndexOf('$readerAssignmentPath =', [StringComparison]::Ordinal)
    }
  }
}
