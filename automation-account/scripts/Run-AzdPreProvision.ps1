[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$TenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\..\shared\scripts\Maester-PreProvision.psm1') -Force

$location = $env:AZURE_LOCATION
Invoke-MaesterPreProvision `
  -SolutionName 'automation-account' `
  -SubscriptionId $SubscriptionId `
  -TenantId $TenantId `
  -Location $location

if (-not $SubscriptionId) {
  $SubscriptionId = $env:AZURE_SUBSCRIPTION_ID
}

# Re-read location from azd env in case the wizard set it during preprovision
if ([string]::IsNullOrWhiteSpace($location)) {
  $postWizardEnvValues = Get-AzdEnvironmentValues
  $location = Get-AzdEnvironmentValue -Values $postWizardEnvValues -Name 'AZURE_LOCATION'
}

# Remove any existing jobSchedules to allow idempotent re-deployment after partial failures
$aaName = $env:automationAccountName
$rgName = $env:AZURE_RESOURCE_GROUP
if (-not [string]::IsNullOrWhiteSpace($aaName) -and -not [string]::IsNullOrWhiteSpace($rgName) -and -not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
  try {
    $jobSchedulesJson = az automation job-schedule list `
      --automation-account-name $aaName `
      --resource-group $rgName `
      --subscription $SubscriptionId `
      -o json 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($jobSchedulesJson)) {
      $jobSchedules = @($jobSchedulesJson | ConvertFrom-Json)
      foreach ($js in $jobSchedules) {
        $jsId = $js.name
        if (-not [string]::IsNullOrWhiteSpace($jsId)) {
          Write-Host "  Removing existing jobSchedule '$jsId' to allow idempotent re-deployment..."
          az automation job-schedule delete `
            --automation-account-name $aaName `
            --resource-group $rgName `
            --subscription $SubscriptionId `
            --job-schedule-id $jsId `
            --yes 2>&1 | Out-Null
        }
      }
    }
  }
  catch {
    Write-Warning "Could not clean up existing jobSchedules: $_"
  }
}

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
