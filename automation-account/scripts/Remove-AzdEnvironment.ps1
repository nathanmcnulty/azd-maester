[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$EnvironmentName,

  [Parameter(Mandatory = $false)]
  [switch]$KeepEnvironment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-EnvValue {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Lines,

    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  foreach ($line in $Lines) {
    if ($line -like "$Name=*") {
      return $line.Split('=', 2)[1].Trim('"')
    }
  }

  return $null
}

function Clear-AzdEnvironmentValue {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  & azd env set "$Name="
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "Failed to clear azd environment value '$Name'."
    return
  }

  Write-Host "Cleared azd environment value '$Name'."
}

function Remove-WebAppEasyAuthEntraApplications {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string[]]$AdditionalApplicationObjectIds,

    [Parameter(Mandatory = $false)]
    [string[]]$AdditionalClientIds
  )

  $applicationObjectIds = New-Object System.Collections.Generic.HashSet[string]
  $clientIds = New-Object System.Collections.Generic.HashSet[string]

  foreach ($additionalObjectId in @($AdditionalApplicationObjectIds)) {
    if (-not [string]::IsNullOrWhiteSpace($additionalObjectId)) {
      [void]$applicationObjectIds.Add($additionalObjectId)
    }
  }

  foreach ($additionalClientId in @($AdditionalClientIds)) {
    if (-not [string]::IsNullOrWhiteSpace($additionalClientId)) {
      [void]$clientIds.Add($additionalClientId)
    }
  }

  $subscriptionArgs = @()
  if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
    $subscriptionArgs = @('--subscription', $SubscriptionId)
  }

  if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
    Write-Host "Discovering Web Apps in '$ResourceGroupName' for Easy Auth Entra app cleanup..."
    $webAppNamesRaw = & az resource list --resource-group $ResourceGroupName --resource-type Microsoft.Web/sites --query '[].name' -o tsv @subscriptionArgs
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Unable to list Web Apps in '$ResourceGroupName'. Continuing with env-based Easy Auth app cleanup only."
    }
    else {
      $webAppNames = @($webAppNamesRaw -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
      foreach ($webAppName in $webAppNames) {
        $authSettingsUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$webAppName/config/authsettingsV2?api-version=2023-12-01"
        $authRaw = & az rest --method get --url $authSettingsUrl @subscriptionArgs
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($authRaw)) {
          continue
        }

        try {
          $auth = $authRaw | ConvertFrom-Json
          $clientId = $auth.properties.identityProviders.azureActiveDirectory.registration.clientId
          if (-not [string]::IsNullOrWhiteSpace($clientId)) {
            [void]$clientIds.Add($clientId)
          }
        }
        catch {
          Write-Warning "Failed to parse authsettingsV2 for Web App '$webAppName'. Skipping."
        }
      }
    }
  }
  else {
    Write-Warning 'AZURE_SUBSCRIPTION_ID is not set. Skipping Web App authsettings discovery and using env-based Easy Auth app cleanup only.'
  }

  $deletedAppObjectIds = New-Object System.Collections.Generic.HashSet[string]
  foreach ($appObjectId in $applicationObjectIds) {
    $applicationRaw = & az rest --method get --url "https://graph.microsoft.com/v1.0/applications/${appObjectId}?`$select=id,appId,displayName"
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($applicationRaw)) {
      Write-Warning "Unable to query Entra application by objectId '$appObjectId'."
      continue
    }

    try {
      $application = $applicationRaw | ConvertFrom-Json
    }
    catch {
      Write-Warning "Failed to parse Entra application lookup for objectId '$appObjectId'."
      continue
    }

    $displayName = if ($application.displayName) { $application.displayName } else { '' }
    if ($displayName -notlike 'maester-easyauth-*') {
      Write-Warning "Skipping Entra application '$displayName' ($($application.id)) because it does not match the expected Easy Auth naming convention."
      continue
    }

    Write-Host "Removing Easy Auth Entra application '$displayName' ($($application.appId))"
    & az rest --method delete --url "https://graph.microsoft.com/v1.0/applications/$($application.id)" | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Failed to remove Entra application '$displayName' ($($application.id))."
      continue
    }

    [void]$deletedAppObjectIds.Add($application.id)
  }

  foreach ($clientId in $clientIds) {
    $appByClientIdRaw = & az ad app show --id $clientId -o json 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($appByClientIdRaw)) {
      continue
    }

    try {
      $appByClientId = $appByClientIdRaw | ConvertFrom-Json
      $apps = @($appByClientId)
    }
    catch {
      Write-Warning "Failed to parse Entra application lookup for appId '$clientId'."
      continue
    }

    if (-not $apps -or $apps.Count -eq 0) {
      continue
    }

    foreach ($app in @($apps)) {
      if ($deletedAppObjectIds.Contains($app.id)) {
        continue
      }

      $displayName = if ($app.displayName) { $app.displayName } else { '' }
      if ($displayName -notlike 'maester-easyauth-*') {
        Write-Warning "Skipping Entra application '$displayName' ($($app.id)) because it does not match the expected Easy Auth naming convention."
        continue
      }

      Write-Host "Removing Easy Auth Entra application '$displayName' ($($app.appId))"
      & az rest --method delete --url "https://graph.microsoft.com/v1.0/applications/$($app.id)" | Out-Null
      if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to remove Entra application '$displayName' ($($app.id))."
        continue
      }

      [void]$deletedAppObjectIds.Add($app.id)
    }
  }
}

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $projectRoot

Write-Host "Selecting azd environment '$EnvironmentName'"
& azd env select $EnvironmentName
if ($LASTEXITCODE -ne 0) {
  throw "Failed to select azd environment '$EnvironmentName'."
}

$resourceGroupName = $null
$subscriptionId = $null
$easyAuthAppObjectId = $null
$easyAuthAppClientId = $null
$envValues = & azd env get-values
if ($LASTEXITCODE -eq 0) {
  $resourceGroupName = Get-EnvValue -Lines $envValues -Name 'AZURE_RESOURCE_GROUP'
  $subscriptionId = Get-EnvValue -Lines $envValues -Name 'AZURE_SUBSCRIPTION_ID'
  $easyAuthAppObjectId = Get-EnvValue -Lines $envValues -Name 'EASY_AUTH_ENTRA_APP_OBJECT_ID'
  $easyAuthAppClientId = Get-EnvValue -Lines $envValues -Name 'EASY_AUTH_ENTRA_APP_CLIENT_ID'
}

if (-not [string]::IsNullOrWhiteSpace($resourceGroupName)) {
  Remove-WebAppEasyAuthEntraApplications `
    -ResourceGroupName $resourceGroupName `
    -SubscriptionId $subscriptionId `
    -AdditionalApplicationObjectIds @($easyAuthAppObjectId) `
    -AdditionalClientIds @($easyAuthAppClientId)

  Write-Host "Removing resource locks in '$resourceGroupName' (if any)..."
  $lockIdsRaw = & az lock list --resource-group $resourceGroupName --query '[].id' -o tsv
  if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($lockIdsRaw)) {
    $lockIds = @($lockIdsRaw -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    foreach ($lockId in $lockIds) {
      & az lock delete --ids $lockId | Out-Null
    }
  }
}

if ($KeepEnvironment) {
  Write-Host 'Running azd down and keeping local environment files.'
  & azd down --force --no-prompt
}
else {
  Write-Host 'Running azd down and purging local environment files.'
  & azd down --force --purge --no-prompt
}

if ($LASTEXITCODE -ne 0) {
  throw 'azd down failed.'
}

if ($KeepEnvironment) {
  Write-Host 'Clearing Easy Auth Entra app metadata from kept azd environment...'
  Clear-AzdEnvironmentValue -Name 'EASY_AUTH_ENTRA_APP_OBJECT_ID'
  Clear-AzdEnvironmentValue -Name 'EASY_AUTH_ENTRA_APP_CLIENT_ID'
  Clear-AzdEnvironmentValue -Name 'EASY_AUTH_ENTRA_APP_DISPLAY_NAME'
}

Write-Host "Environment removal completed for '$EnvironmentName'."