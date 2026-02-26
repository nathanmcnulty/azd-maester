# Shared PowerShell helper functions for azd-maester solutions
# This module is imported by solution scripts to avoid duplication.

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

function Test-CanPrompt {
  try {
    $null = $Host.UI.RawUI
    return $true
  }
  catch {
    return $false
  }
}

function ConvertFrom-JsonArrayOrEmpty {
  param(
    [Parameter(Mandatory = $false)]
    [string]$Json
  )
  if ([string]::IsNullOrWhiteSpace($Json)) {
    return @()
  }
  $text = $Json.Trim()
  if (-not $text.StartsWith('[')) {
    return @($text -split ';' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  }
  try {
    $parsed = $text | ConvertFrom-Json
    if (-not $parsed) {
      return @()
    }
    if ($parsed -is [string]) {
      return @($parsed)
    }
    return @($parsed)
  }
  catch {
    Write-Warning "Failed to parse JSON array value. Skipping. Value: $Json"
    return @()
  }
}

function Test-ModuleAvailable {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ModuleName
  )
  $available = Get-Module -ListAvailable -Name $ModuleName | Select-Object -First 1
  if ($available) {
    Import-Module $ModuleName -Force
    return $true
  }
  if (-not (Test-CanPrompt)) {
    Write-Warning "$ModuleName is not installed and this is a non-interactive session."
    return $false
  }
  $installChoice = Read-Host "Install PowerShell module '$ModuleName' now? (Y/N)"
  if (-not $installChoice -or $installChoice.Trim().ToUpper() -ne 'Y') {
    return $false
  }
  Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
  Import-Module $ModuleName -Force
  return $true
}

function Invoke-Azd {
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string[]]$Arguments,

    [Parameter(Mandatory = $true)]
    [string]$Operation
  )

  & azd @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "azd command failed during: $Operation"
  }
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
          $clientId = $null

          if ($auth.PSObject.Properties['properties'] -and
              $auth.properties.PSObject.Properties['identityProviders'] -and
              $auth.properties.identityProviders.PSObject.Properties['azureActiveDirectory'] -and
              $auth.properties.identityProviders.azureActiveDirectory.PSObject.Properties['registration'] -and
              $auth.properties.identityProviders.azureActiveDirectory.registration.PSObject.Properties['clientId']) {
            $clientId = $auth.properties.identityProviders.azureActiveDirectory.registration.clientId
          }

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
