# Shared azd up wizard for azd-maester solutions.
# Runs during preprovision to collect and persist solution options.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'Maester-SetupHelpers.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Maester-Helpers.psm1') -Force

function ConvertTo-BoolOrNull {
  param(
    [Parameter(Mandatory = $false)]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return $null
  }

  switch ($Value.Trim().ToLower()) {
    'true' { return $true }
    'false' { return $false }
    default { return $null }
  }
}

function Set-AzdEnvValueStrict {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$Value
  )

  & azd env set $Name $Value | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to persist azd environment value '$Name'."
  }
}

function Test-InteractiveWizard {
  if ($env:AZD_NON_INTERACTIVE -eq 'true' -or
      $env:CI -eq 'true' -or
      (Test-AzdNoPromptInvocation)) {
    return $false
  }

  try {
    $null = $Host.UI.RawUI
  }
  catch {
    return $false
  }

  return $true
}

function Test-AzdNoPromptInvocation {
  try {
    $currentPid = $PID
    for ($depth = 0; $depth -lt 10; $depth++) {
      $process = Get-CimInstance Win32_Process -Filter "ProcessId = $currentPid" -ErrorAction Stop
      if (-not $process) {
        break
      }

      $name = [string]$process.Name
      $commandLine = [string]$process.CommandLine

      if ($name -ieq 'azd.exe' -and
          -not [string]::IsNullOrWhiteSpace($commandLine) -and
          $commandLine -match '(^|\s)--no-prompt(\s|$)') {
        return $true
      }

      $parentPid = [int]$process.ParentProcessId
      if ($parentPid -le 0 -or $parentPid -eq $currentPid) {
        break
      }

      $currentPid = $parentPid
    }
  }
  catch {
  }

  return $false
}

function Read-BoolChoice {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Prompt,

    [Parameter(Mandatory = $false)]
    [AllowNull()]
    $CurrentValue,

    [Parameter(Mandatory = $true)]
    [bool]$InteractiveDefault,

    [Parameter(Mandatory = $true)]
    [bool]$InteractiveWizard
  )

  $hasCurrentValue = $null -ne $CurrentValue
  $currentValueBool = if ($hasCurrentValue) { [bool]$CurrentValue } else { $false }

  if (-not $InteractiveWizard) {
    if ($hasCurrentValue) {
      return $currentValueBool
    }

    return $false
  }

  $defaultValue = if ($hasCurrentValue) { $currentValueBool } else { $InteractiveDefault }
  $hint = if ($defaultValue) { '[Y/n]' } else { '[y/N]' }

  while ($true) {
    $inputValue = Read-Host "$Prompt $hint"
    if ([string]::IsNullOrWhiteSpace($inputValue)) {
      return $defaultValue
    }

    switch ($inputValue.Trim().ToLower()) {
      'y' { return $true }
      'yes' { return $true }
      'true' { return $true }
      '1' { return $true }
      'n' { return $false }
      'no' { return $false }
      'false' { return $false }
      '0' { return $false }
      default { Write-Host "Please enter 'Y' or 'N'." }
    }
  }
}

function Read-TextChoice {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Prompt,

    [Parameter(Mandatory = $false)]
    [AllowEmptyString()]
    [string]$CurrentValue,

    [Parameter(Mandatory = $false)]
    [AllowEmptyString()]
    [string]$FallbackValue = '',

    [Parameter(Mandatory = $true)]
    [bool]$AllowEmpty,

    [Parameter(Mandatory = $true)]
    [bool]$InteractiveWizard
  )

  $defaultValue = if ($null -ne $CurrentValue -and $CurrentValue -ne '') {
    $CurrentValue
  }
  else {
    $FallbackValue
  }

  if (-not $InteractiveWizard) {
    if (-not [string]::IsNullOrWhiteSpace($defaultValue)) {
      return $defaultValue
    }

    if ($AllowEmpty) {
      return ''
    }

    throw "$Prompt is required for non-interactive runs."
  }

  while ($true) {
    $renderedPrompt = if (-not [string]::IsNullOrWhiteSpace($defaultValue)) {
      "$Prompt [$defaultValue]"
    }
    else {
      $Prompt
    }

    $inputValue = Read-Host $renderedPrompt
    if ([string]::IsNullOrWhiteSpace($inputValue)) {
      if (-not [string]::IsNullOrWhiteSpace($defaultValue)) {
        return $defaultValue
      }

      if ($AllowEmpty) {
        return ''
      }

      Write-Host 'A value is required.'
      continue
    }

    return $inputValue.Trim()
  }
}

function ConvertFrom-AzureScopes {
  param(
    [Parameter(Mandatory = $false)]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return @()
  }

  return @($Value -split ';' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function ConvertTo-AzureScopes {
  param(
    [Parameter(Mandatory = $false)]
    [string[]]$Scopes
  )

  return (@($Scopes) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) -join ';'
}

function Resolve-AzureScopes {
  param(
    [Parameter(Mandatory = $true)]
    [bool]$IncludeAzure,

    [Parameter(Mandatory = $true)]
    [bool]$InteractiveWizard,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [AllowEmptyCollection()]
    [string[]]$ExistingScopes = @(),

    [Parameter(Mandatory = $true)]
    [string]$ResourceTypeName
  )

  if (-not $IncludeAzure) {
    return ''
  }

  if (-not $InteractiveWizard) {
    if ($ExistingScopes.Count -gt 0) {
      return (ConvertTo-AzureScopes -Scopes $ExistingScopes)
    }

    return "/subscriptions/$SubscriptionId"
  }

  if ($ExistingScopes.Count -gt 0) {
    $existingText = $ExistingScopes -join '; '
    $useExisting = Read-BoolChoice `
      -Prompt "Reuse existing Azure RBAC scopes ($existingText)?" `
      -CurrentValue $true `
      -InteractiveDefault $true `
      -InteractiveWizard $true
    if ($useExisting) {
      return (ConvertTo-AzureScopes -Scopes $ExistingScopes)
    }
  }

  $selectedScopes = Select-AzureRbacScopes -DefaultSubscriptionId $SubscriptionId -ResourceTypeName $ResourceTypeName
  return (ConvertTo-AzureScopes -Scopes $selectedScopes)
}

function Get-LocationOrDefault {
  param(
    [Parameter(Mandatory = $false)]
    [string]$Location
  )

  if (-not [string]::IsNullOrWhiteSpace($Location)) {
    return $Location
  }

  if (-not [string]::IsNullOrWhiteSpace($env:AZURE_LOCATION)) {
    return $env:AZURE_LOCATION
  }

  return 'eastus2'
}

function Invoke-MaesterUpWizard {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('automation-account', 'function-app', 'container-app-job', 'azure-devops')]
    [string]$SolutionName,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$Location,

    [Parameter(Mandatory = $false)]
    [string]$TenantId
  )

  $interactiveWizard = Test-InteractiveWizard
  $envValues = Get-AzdEnvironmentValues

  $environmentName = if (-not [string]::IsNullOrWhiteSpace($env:AZURE_ENV_NAME)) { $env:AZURE_ENV_NAME } else { 'dev' }
  $effectiveLocation = Get-LocationOrDefault -Location $Location
  $normalizedLocation = ($effectiveLocation -replace '\s+', '').ToLower()

  $resourceGroupCurrent = Get-AzdEnvironmentValue -Values $envValues -Name 'AZURE_RESOURCE_GROUP'
  $resourceGroupDefault = if (-not [string]::IsNullOrWhiteSpace($resourceGroupCurrent)) {
    $resourceGroupCurrent
  }
  else {
    "rg-$($environmentName.ToLower())-$normalizedLocation"
  }

  $includeWebAppCurrent = ConvertTo-BoolOrNull (Get-AzdEnvironmentValue -Values $envValues -Name 'INCLUDE_WEB_APP')
  $includeExchangeCurrent = ConvertTo-BoolOrNull (Get-AzdEnvironmentValue -Values $envValues -Name 'INCLUDE_EXCHANGE')
  $includeTeamsCurrent = ConvertTo-BoolOrNull (Get-AzdEnvironmentValue -Values $envValues -Name 'INCLUDE_TEAMS')
  $includeAzureCurrent = ConvertTo-BoolOrNull (Get-AzdEnvironmentValue -Values $envValues -Name 'INCLUDE_AZURE')
  $includeAcrCurrent = ConvertTo-BoolOrNull (Get-AzdEnvironmentValue -Values $envValues -Name 'INCLUDE_ACR')

  $mailRecipientCurrent = Get-AzdEnvironmentValue -Values $envValues -Name 'MAIL_RECIPIENT'
  $permissionProfileCurrent = Get-AzdEnvironmentValue -Values $envValues -Name 'PERMISSION_PROFILE'
  $webAppSkuCurrent = Get-AzdEnvironmentValue -Values $envValues -Name 'WEB_APP_SKU'
  $securityGroupObjectIdCurrent = Get-AzdEnvironmentValue -Values $envValues -Name 'SECURITY_GROUP_OBJECT_ID'
  if ([string]::IsNullOrWhiteSpace($securityGroupObjectIdCurrent)) {
    $securityGroupObjectIdCurrent = Get-AzdEnvironmentValue -Values $envValues -Name 'EASY_AUTH_SECURITY_GROUP_OBJECT_ID'
  }
  $securityGroupDisplayNameCurrent = Get-AzdEnvironmentValue -Values $envValues -Name 'SECURITY_GROUP_DISPLAY_NAME'
  $azureScopesCurrent = @(ConvertFrom-AzureScopes -Value (Get-AzdEnvironmentValue -Values $envValues -Name 'AZURE_RBAC_SCOPES'))

  $includeWebApp = Read-BoolChoice -Prompt 'Include Web App?' -CurrentValue $includeWebAppCurrent -InteractiveDefault $true -InteractiveWizard $interactiveWizard
  $includeExchange = Read-BoolChoice -Prompt 'Include Exchange?' -CurrentValue $includeExchangeCurrent -InteractiveDefault $true -InteractiveWizard $interactiveWizard
  $includeTeams = Read-BoolChoice -Prompt 'Include Teams?' -CurrentValue $includeTeamsCurrent -InteractiveDefault $true -InteractiveWizard $interactiveWizard
  $includeAzure = Read-BoolChoice -Prompt 'Include Azure?' -CurrentValue $includeAzureCurrent -InteractiveDefault $true -InteractiveWizard $interactiveWizard

  $includeAcr = $false
  if ($SolutionName -eq 'container-app-job') {
    $includeAcr = Read-BoolChoice -Prompt 'Include ACR?' -CurrentValue $includeAcrCurrent -InteractiveDefault $false -InteractiveWizard $interactiveWizard
  }

  $mailRecipient = Read-TextChoice `
    -Prompt 'Mail recipient (leave blank to disable email notifications)' `
    -CurrentValue $mailRecipientCurrent `
    -FallbackValue '' `
    -AllowEmpty $true `
    -InteractiveWizard $interactiveWizard

  $webAppSku = if ([string]::IsNullOrWhiteSpace($webAppSkuCurrent)) { 'F1' } else { $webAppSkuCurrent }
  $permissionProfile = if ([string]::IsNullOrWhiteSpace($permissionProfileCurrent)) { 'Extended' } else { $permissionProfileCurrent }

  $securityGroupObjectId = $securityGroupObjectIdCurrent
  if ($includeWebApp) {
    $securityGroupObjectId = Read-TextChoice `
      -Prompt 'Security group object ID for Web App Easy Auth' `
      -CurrentValue $securityGroupObjectIdCurrent `
      -FallbackValue '' `
      -AllowEmpty $false `
      -InteractiveWizard $interactiveWizard
  }

  $azureScopesSerialized = Resolve-AzureScopes `
    -IncludeAzure $includeAzure `
    -InteractiveWizard $interactiveWizard `
    -SubscriptionId $SubscriptionId `
    -ExistingScopes $azureScopesCurrent `
    -ResourceTypeName $SolutionName

  Set-AzdEnvValueStrict -Name 'AZURE_RESOURCE_GROUP' -Value $resourceGroupDefault
  Set-AzdEnvValueStrict -Name 'INCLUDE_WEB_APP' -Value $includeWebApp.ToString().ToLower()
  Set-AzdEnvValueStrict -Name 'INCLUDE_EXCHANGE' -Value $includeExchange.ToString().ToLower()
  Set-AzdEnvValueStrict -Name 'INCLUDE_TEAMS' -Value $includeTeams.ToString().ToLower()
  Set-AzdEnvValueStrict -Name 'INCLUDE_AZURE' -Value $includeAzure.ToString().ToLower()
  Set-AzdEnvValueStrict -Name 'WEB_APP_SKU' -Value $webAppSku
  Set-AzdEnvValueStrict -Name 'PERMISSION_PROFILE' -Value $permissionProfile
  Set-AzdEnvValueStrict -Name 'MAIL_RECIPIENT' -Value $mailRecipient
  Set-AzdEnvValueStrict -Name 'AZURE_RBAC_SCOPES' -Value $azureScopesSerialized

  if ($includeWebApp) {
    Set-AzdEnvValueStrict -Name 'SECURITY_GROUP_OBJECT_ID' -Value $securityGroupObjectId
    if (-not [string]::IsNullOrWhiteSpace($securityGroupDisplayNameCurrent)) {
      Set-AzdEnvValueStrict -Name 'SECURITY_GROUP_DISPLAY_NAME' -Value $securityGroupDisplayNameCurrent
    }
  }

  switch ($SolutionName) {
    'automation-account' {
      Set-AzdEnvValueStrict -Name 'VALIDATE_RUNBOOK_ON_PROVISION' -Value 'true'
    }

    'function-app' {
      $functionPlanCurrent = Get-AzdEnvironmentValue -Values $envValues -Name 'FUNCTION_APP_PLAN'
      $functionPlan = if ([string]::IsNullOrWhiteSpace($functionPlanCurrent)) { 'FC1' } else { $functionPlanCurrent }
      Set-AzdEnvValueStrict -Name 'FUNCTION_APP_PLAN' -Value $functionPlan
      Set-AzdEnvValueStrict -Name 'VALIDATE_FUNCTION_ON_PROVISION' -Value 'true'
    }

    'container-app-job' {
      Set-AzdEnvValueStrict -Name 'INCLUDE_ACR' -Value $includeAcr.ToString().ToLower()
      Set-AzdEnvValueStrict -Name 'VALIDATE_JOB_ON_PROVISION' -Value 'true'
    }

    'azure-devops' {
      $organizationCurrent = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_ORGANIZATION'
      $projectCurrent = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_PROJECT'

      $organization = Read-TextChoice `
        -Prompt 'Azure DevOps organization (dev.azure.com/<org>)' `
        -CurrentValue $organizationCurrent `
        -FallbackValue '' `
        -AllowEmpty $false `
        -InteractiveWizard $interactiveWizard

      $project = Read-TextChoice `
        -Prompt 'Azure DevOps project' `
        -CurrentValue $projectCurrent `
        -FallbackValue '' `
        -AllowEmpty $false `
        -InteractiveWizard $interactiveWizard

      $envLower = $environmentName.ToLower()
      $repositoryName = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_REPOSITORY'
      if ([string]::IsNullOrWhiteSpace($repositoryName)) {
        $repositoryName = "maester-$envLower"
      }
      $pipelineName = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_PIPELINE_NAME'
      if ([string]::IsNullOrWhiteSpace($pipelineName)) {
        $pipelineName = 'maester-weekly'
      }
      $serviceConnectionName = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_SERVICE_CONNECTION_NAME'
      if ([string]::IsNullOrWhiteSpace($serviceConnectionName)) {
        $serviceConnectionName = "sc-maester-$envLower"
      }
      $pipelineYamlPath = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_PIPELINE_YAML_PATH'
      if ([string]::IsNullOrWhiteSpace($pipelineYamlPath)) {
        $pipelineYamlPath = '/azure-pipelines.yml'
      }
      $defaultBranch = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_DEFAULT_BRANCH'
      if ([string]::IsNullOrWhiteSpace($defaultBranch)) {
        $defaultBranch = 'main'
      }
      $scheduleCron = Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_SCHEDULE_CRON'
      if ([string]::IsNullOrWhiteSpace($scheduleCron)) {
        $scheduleCron = '0 0 * * 0'
      }

      $createRepoCurrent = ConvertTo-BoolOrNull (Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_CREATE_REPO_IF_MISSING')
      $pushFilesCurrent = ConvertTo-BoolOrNull (Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_PUSH_PIPELINE_FILES')
      $validateRunCurrent = ConvertTo-BoolOrNull (Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_VALIDATE_PIPELINE_RUN')
      $failTestsCurrent = ConvertTo-BoolOrNull (Get-AzdEnvironmentValue -Values $envValues -Name 'AZDO_FAIL_ON_TEST_FAILURES')

      $createRepo = if ($null -ne $createRepoCurrent) { [bool]$createRepoCurrent } else { $true }
      $pushFiles = if ($null -ne $pushFilesCurrent) { [bool]$pushFilesCurrent } else { $true }
      $validateRun = if ($null -ne $validateRunCurrent) { [bool]$validateRunCurrent } else { $true }
      $failTests = if ($null -ne $failTestsCurrent) { [bool]$failTestsCurrent } else { $true }

      Set-AzdEnvValueStrict -Name 'AZDO_ORGANIZATION' -Value $organization
      Set-AzdEnvValueStrict -Name 'AZDO_PROJECT' -Value $project
      Set-AzdEnvValueStrict -Name 'AZDO_REPOSITORY' -Value $repositoryName
      Set-AzdEnvValueStrict -Name 'AZDO_PIPELINE_NAME' -Value $pipelineName
      Set-AzdEnvValueStrict -Name 'AZDO_SERVICE_CONNECTION_NAME' -Value $serviceConnectionName
      Set-AzdEnvValueStrict -Name 'AZDO_PIPELINE_YAML_PATH' -Value $pipelineYamlPath
      Set-AzdEnvValueStrict -Name 'AZDO_DEFAULT_BRANCH' -Value $defaultBranch
      Set-AzdEnvValueStrict -Name 'AZDO_SCHEDULE_CRON' -Value $scheduleCron
      Set-AzdEnvValueStrict -Name 'AZDO_CREATE_REPO_IF_MISSING' -Value $createRepo.ToString().ToLower()
      Set-AzdEnvValueStrict -Name 'AZDO_PUSH_PIPELINE_FILES' -Value $pushFiles.ToString().ToLower()
      Set-AzdEnvValueStrict -Name 'AZDO_VALIDATE_PIPELINE_RUN' -Value $validateRun.ToString().ToLower()
      Set-AzdEnvValueStrict -Name 'AZDO_FAIL_ON_TEST_FAILURES' -Value $failTests.ToString().ToLower()
      Set-AzdEnvValueStrict -Name 'VALIDATE_PIPELINE_ON_PROVISION' -Value $validateRun.ToString().ToLower()
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
    Set-AzdEnvValueStrict -Name 'AZURE_TENANT_ID' -Value $TenantId
  }

  Write-Host 'azd preprovision wizard settings applied.'
}

Export-ModuleMember -Function Invoke-MaesterUpWizard
