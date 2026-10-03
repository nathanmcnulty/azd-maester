[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$TenantId,

  [Parameter(Mandatory = $false)]
  [string]$EnvironmentName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $EnvironmentName) { $EnvironmentName = $env:AZURE_ENV_NAME }
if ([string]::IsNullOrWhiteSpace($EnvironmentName) -or
    ($env:AZURE_ENV_NAME -and $env:AZURE_ENV_NAME -cne $EnvironmentName)) {
  throw 'The requested azd environment does not match the hook environment.'
}
Import-Module (Join-Path $PSScriptRoot 'Resolve-DeploymentTarget.psm1') -Force
. (Join-Path $PSScriptRoot 'JobScheduleOwnership.ps1')
# The pinned wizard uses the current azd selection. Check it before mutation.
$expectedSubscriptionId = if ($SubscriptionId) { $SubscriptionId } else { $env:AZURE_SUBSCRIPTION_ID }
$expectedTenantId = if ($TenantId) { $TenantId } else { $env:AZURE_TENANT_ID }
$null = Assert-MaesterAzdSelectedEnvironment -EnvironmentName $EnvironmentName -ProjectRoot $projectRoot `
  -SubscriptionId $expectedSubscriptionId -TenantId $expectedTenantId

Import-Module (Join-Path $PSScriptRoot 'vendor\Azd.MaesterHooks\Maester-PreProvision.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'vendor\Azd.MaesterHooks\Maester-Helpers.psm1') -Force

$location = $env:AZURE_LOCATION
Invoke-MaesterPreProvision `
  -SolutionName 'automation-account' `
  -SubscriptionId $SubscriptionId `
  -TenantId $TenantId `
  -Location $location

$null = Assert-MaesterAzdSelectedEnvironment -EnvironmentName $EnvironmentName -ProjectRoot $projectRoot `
  -SubscriptionId $expectedSubscriptionId -TenantId $expectedTenantId
$selectedJson = & azd env get-values --output json -e $EnvironmentName --cwd $projectRoot 2>$null
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($selectedJson | Out-String))) {
  throw 'Could not read the selected azd environment after the preprovision wizard.'
}
try { $selectedValues = $selectedJson | ConvertFrom-Json -AsHashtable }
catch { throw 'The selected azd environment returned invalid values after preprovision.' }
if ($LASTEXITCODE -ne 0 -or -not $selectedValues -or $selectedValues['AZURE_ENV_NAME'] -ine $EnvironmentName) {
  throw 'Could not verify the selected azd environment after the preprovision wizard.'
}
if (($env:AZURE_SUBSCRIPTION_ID -and $selectedValues['AZURE_SUBSCRIPTION_ID'] -ine $env:AZURE_SUBSCRIPTION_ID) -or
    ($env:AZURE_TENANT_ID -and $selectedValues['AZURE_TENANT_ID'] -ine $env:AZURE_TENANT_ID) -or
    ($TenantId -and $selectedValues['AZURE_TENANT_ID'] -ine $TenantId)) {
  throw 'The preprovision wizard selected a different Azure target.'
}
if (-not $SubscriptionId) { $SubscriptionId = [string]$selectedValues['AZURE_SUBSCRIPTION_ID'] }
$rgName = [string]$selectedValues['AZURE_RESOURCE_GROUP']
if ([string]::IsNullOrWhiteSpace($SubscriptionId) -or $selectedValues['AZURE_SUBSCRIPTION_ID'] -ine $SubscriptionId) {
  throw 'The selected azd environment has no matching subscription.'
}
if ([string]::IsNullOrWhiteSpace($location)) { $location = [string]$selectedValues['AZURE_LOCATION'] }
$aaName = "aa-$($EnvironmentName.ToLower())"
$priorOwnership = @(@('AUTOMATION_OWNED_ACCOUNT_ID', 'AUTOMATION_OWNED_PRINCIPAL_ID', 'AUTOMATION_OWNED_JOB_SCHEDULE_ID',
  'AUTOMATION_ADOPT_ACCOUNT_ID', 'AUTOMATION_ADOPT_PRINCIPAL_ID', 'AUTOMATION_ADOPT_JOB_SCHEDULE_ID') |
  Where-Object { -not [string]::IsNullOrWhiteSpace([string]$selectedValues[$_]) })
$resourceGroupExists = $false
if (-not [string]::IsNullOrWhiteSpace($rgName)) {
  $existsResult = & az group exists --name $rgName --subscription $SubscriptionId -o tsv
  if ($LASTEXITCODE -ne 0 -or [string]$existsResult -notin @('true', 'false')) {
    throw 'Could not verify whether the target resource group exists.'
  }
  $resourceGroupExists = [string]$existsResult -eq 'true'
}
if (-not $resourceGroupExists -and $priorOwnership.Count -gt 0) {
  throw 'An Automation ownership receipt or adoption request exists, but its target resource group is absent.'
}
$expectedAccountId = if ($resourceGroupExists) {
  "/subscriptions/$SubscriptionId/resourceGroups/$rgName/providers/Microsoft.Automation/automationAccounts/$aaName"
} else { '' }

# Read the complete inventory before deciding whether an exact prior association can be reused.
$account = $null
$jobSchedules = @()
if ($resourceGroupExists) {
  $accountListUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$rgName/providers/Microsoft.Automation/automationAccounts?api-version=2023-11-01"
  $accountListJson = & az rest --method GET --uri $accountListUri --subscription $SubscriptionId -o json
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($accountListJson)) { throw 'Could not inspect Automation accounts in the target resource group.' }
  $accountList = $accountListJson | ConvertFrom-Json -ErrorAction Stop
  if ($null -eq $accountList.value -or $accountList.value -isnot [System.Collections.IList] -or
      ($accountList.PSObject.Properties['nextLink'] -and $accountList.nextLink)) {
    throw 'Automation account inventory was incomplete.'
  }
  $matchingAccounts = @($accountList.value | Where-Object { $_.name -ieq $aaName })
  if ($matchingAccounts.Count -gt 1) { throw 'Automation account inventory has duplicate target names.' }
}
if ($resourceGroupExists -and $matchingAccounts.Count -eq 1) {
  $accountJson = & az rest --method GET --uri "https://management.azure.com$expectedAccountId`?api-version=2023-11-01" --subscription $SubscriptionId -o json
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($accountJson)) { throw 'Could not inspect the exact Automation account.' }
  $account = $accountJson | ConvertFrom-Json -ErrorAction Stop
  if ($account.id -ine $expectedAccountId -or $account.name -ine $aaName -or
      $account.type -ine 'Microsoft.Automation/automationAccounts' -or
      -not $account.tags -or $account.tags.workload -ine 'maester' -or
      $account.tags.solution -ine 'automation-account' -or
      $account.tags.environment -ine $EnvironmentName -or $account.tags.managedBy -ine 'azd') {
    throw 'The exact Automation account does not match the template deployment target.'
  }
  $schedulesUri = "https://management.azure.com$expectedAccountId/jobSchedules?api-version=2023-11-01"
  $schedulesJson = & az rest --method GET --uri $schedulesUri --subscription $SubscriptionId -o json
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($schedulesJson)) { throw 'Could not inspect live Automation jobSchedules.' }
  $schedulesResponse = $schedulesJson | ConvertFrom-Json -ErrorAction Stop
  if ($null -eq $schedulesResponse.value -or $schedulesResponse.value -isnot [System.Collections.IList] -or
      ($schedulesResponse.PSObject.Properties['nextLink'] -and $schedulesResponse.nextLink)) {
    throw 'Automation jobSchedule inventory was incomplete.'
  }
  $jobSchedules = @($schedulesResponse.value)
}

$ownership = if ($resourceGroupExists) {
  Resolve-MaesterJobScheduleOwnership -ExpectedAccountId $expectedAccountId -Account $account -JobSchedules $jobSchedules `
    -ReceiptAccountId ([string]$selectedValues['AUTOMATION_OWNED_ACCOUNT_ID']) `
    -ReceiptPrincipalId ([string]$selectedValues['AUTOMATION_OWNED_PRINCIPAL_ID']) `
    -ReceiptJobScheduleId ([string]$selectedValues['AUTOMATION_OWNED_JOB_SCHEDULE_ID']) `
    -AdoptAccountId ([string]$selectedValues['AUTOMATION_ADOPT_ACCOUNT_ID']) `
    -AdoptPrincipalId ([string]$selectedValues['AUTOMATION_ADOPT_PRINCIPAL_ID']) `
    -AdoptJobScheduleId ([string]$selectedValues['AUTOMATION_ADOPT_JOB_SCHEDULE_ID'])
} else {
  [pscustomobject]@{ JobScheduleId = [guid]::NewGuid().ToString(); OwnedJobScheduleId = '' }
}

if ($ownership.OwnedJobScheduleId) {
  Write-Host "Verified existing template jobSchedule '$($ownership.OwnedJobScheduleId)'; its linkage and resource lock remain intact."
}
Set-MaesterAzdValue -EnvironmentName $EnvironmentName -ProjectRoot $projectRoot -Name 'AUTOMATION_JOB_SCHEDULE_ID' -Value $ownership.JobScheduleId
# Check Automation Account quota in the target region
if ($location) {
  Write-Host "Checking Automation Account quota in region '$location'..."
  try {
    $existingAccountsJson = az automation account list --subscription $SubscriptionId --query "[?location=='$location']" -o json 2>$null
    if ($LASTEXITCODE -eq 0 -and $existingAccountsJson) {
      $existingAccounts = $existingAccountsJson | ConvertFrom-Json
      $count = @($existingAccounts).Count
      # Quota varies by subscription type: Enterprise/CSP = 10, PAYG/MSDN = 2, Free Trial = 1
      if ($count -ge 10) {
        throw "There are already $count Automation Accounts in region '$location'. This exceeds the maximum quota (10 for Enterprise, 2 for PAYG). Provision will fail. Delete unused Automation Accounts or choose a different region."
      }
      elseif ($count -ge 2) {
        Write-Warning "There are already $count Automation Accounts in region '$location'. The quota is 2 for Pay-as-you-go/MSDN subscriptions (10 for Enterprise/CSP). If your subscription type has a lower limit, provision may fail."
      }
      Write-Host "  Found $count existing Automation Account(s) in '$location'."
    }
  }
  catch [System.Management.Automation.RuntimeException] {
    throw
  }
  catch {
    Write-Warning "Could not check Automation Account quota: $_"
  }
}
else {
  Write-Warning 'AZURE_LOCATION not set. Skipping Automation Account quota check.'
}
