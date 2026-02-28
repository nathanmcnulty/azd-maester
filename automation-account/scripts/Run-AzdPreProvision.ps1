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

# Manage jobSchedule GUID for idempotent deployment.
# Azure Automation caches jobSchedule GUIDs at service level beyond ARM resource lifecycle —
# the same GUID cannot be reused after the resource group is deleted (ghost state).
# If the AA exists: remove lock, delete live jobSchedules, reuse stored GUID.
# If the AA is gone: generate a fresh GUID to avoid ghost-state conflicts.
$storedGuid = $env:AUTOMATION_JOB_SCHEDULE_ID
$aaName = $env:automationAccountName
$rgName = $env:AZURE_RESOURCE_GROUP

# Default to a fresh GUID; refined below if the AA exists and we can reuse the stored one.
$jobScheduleId = [System.Guid]::NewGuid().ToString()

try {
  $aaExists = $false
  if (-not [string]::IsNullOrWhiteSpace($aaName) -and -not [string]::IsNullOrWhiteSpace($rgName) -and -not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
    $aaJson = az automation account show --name $aaName --resource-group $rgName --subscription $SubscriptionId -o json 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($aaJson)) {
      $aaExists = $true
    }
  }

  if ($aaExists) {
    Write-Host 'Automation Account exists. Removing resource lock and cleaning up live jobSchedules for re-deployment...'

    # Remove CanNotDelete lock so jobSchedules can be deleted (bicep will re-create it)
    $lockId = "/subscriptions/$SubscriptionId/resourceGroups/$rgName/providers/Microsoft.Automation/automationAccounts/$aaName/providers/Microsoft.Authorization/locks/lock-cannot-delete-automation"
    az lock delete --ids $lockId --subscription $SubscriptionId 2>&1 | Out-Null

    # List and delete all live jobSchedules via REST API
    # (az automation job-schedule CLI subcommand does not exist)
    $listUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$rgName/providers/Microsoft.Automation/automationAccounts/$aaName/jobSchedules?api-version=2023-11-01"
    $listJson = az rest --method GET --uri $listUri -o json 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($listJson)) {
      $liveSchedules = @(($listJson | ConvertFrom-Json).value)
      foreach ($js in $liveSchedules) {
        $jsId = $js.name
        if (-not [string]::IsNullOrWhiteSpace($jsId)) {
          Write-Host "  Deleting live jobSchedule '$jsId'..."
          $deleteUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$rgName/providers/Microsoft.Automation/automationAccounts/$aaName/jobSchedules/${jsId}?api-version=2023-11-01"
          az rest --method DELETE --uri $deleteUri 2>&1 | Out-Null
        }
      }
    }

    # Reuse the stored GUID — it was live and just cleaned up, safe to redeploy with same ID
    if (-not [string]::IsNullOrWhiteSpace($storedGuid)) {
      $jobScheduleId = $storedGuid
      Write-Host "  Reusing stored jobSchedule GUID: $jobScheduleId"
    }
    else {
      Write-Host "  Generated new jobSchedule GUID: $jobScheduleId"
    }
  }
  else {
    # AA does not exist — fresh GUID avoids ghost-state conflicts in Azure Automation service
    Write-Host "Automation Account not found. Generated fresh jobSchedule GUID: $jobScheduleId"
  }
}
catch {
  Write-Warning "Could not manage jobSchedule state: $_"
  Write-Host "Using fallback jobSchedule GUID: $jobScheduleId"
}

& azd env set AUTOMATION_JOB_SCHEDULE_ID $jobScheduleId

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
