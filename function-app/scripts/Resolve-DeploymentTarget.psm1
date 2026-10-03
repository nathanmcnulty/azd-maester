Set-StrictMode -Version Latest

function Select-ExactMaesterResource {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Payload,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$ProviderType,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$EnvironmentName,
    [Parameter(Mandatory)][string]$SolutionName,
    [ValidateSet('Any', 'FunctionApp', 'WebApp')][string]$Kind = 'Any'
  )

  if ($Name -notmatch '^[A-Za-z0-9-]{1,80}$') {
    throw "The exact $ProviderType deployment output is missing or invalid."
  }
  if ($Payload.PSObject.Properties['nextLink'] -and $Payload.nextLink) {
    throw "The $ProviderType resource inventory is incomplete; refusing to select '$Name'."
  }

  $matches = @($Payload.value | Where-Object { $_.name -eq $Name })
  if ($matches.Count -ne 1) {
    throw "Expected exactly one $ProviderType resource named '$Name' in the selected resource group."
  }

  $resource = $matches[0]
  $expectedId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/$ProviderType/$Name"
  if ($resource.type -ine $ProviderType -or $resource.id -ine $expectedId -or
      -not $resource.PSObject.Properties['tags'] -or -not $resource.tags -or
      $resource.tags.workload -ine 'maester' -or
      $resource.tags.solution -ine $SolutionName -or
      $resource.tags.environment -ine $EnvironmentName -or
      $resource.tags.managedBy -ine 'azd') {
    throw "Resource '$Name' does not match the selected Maester deployment identity."
  }
  if ($Kind -eq 'FunctionApp' -and $resource.kind -notmatch '(^|,)functionapp(,|$)') {
    throw "Resource '$Name' is not the expected Function App."
  }
  if ($Kind -eq 'WebApp' -and ($resource.kind -match '(^|,)functionapp(,|$)' -or
      [string]::IsNullOrWhiteSpace([string]$resource.kind))) {
    throw "Resource '$Name' is not the expected Web App."
  }

  return $resource
}

function Select-UniqueGraphApplication {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Response,
    [Parameter(Mandatory)][string]$ExpectedValue,
    [ValidateSet('AppId', 'DisplayName')][string]$MatchBy = 'DisplayName'
  )

  if (-not $Response.PSObject.Properties['value']) {
    throw "The Graph application lookup for '$ExpectedValue' did not return a complete result."
  }
  if ($null -eq $Response.value -or $Response.value -isnot [array]) {
    throw "The Graph application lookup for '$ExpectedValue' returned a malformed collection."
  }
  if ($Response.PSObject.Properties['@odata.nextLink'] -and $Response.'@odata.nextLink') {
    throw "The Graph application lookup for '$ExpectedValue' is incomplete."
  }
  $matches = @($Response.value | Where-Object { $null -ne $_ })
  if ($matches.Count -gt 1) {
    throw "Multiple Graph applications match '$ExpectedValue'."
  }
  if ($matches.Count -eq 0) { return $null }

  $app = $matches[0]
  if ([string]::IsNullOrWhiteSpace([string]$app.id) -or
      [string]::IsNullOrWhiteSpace([string]$app.appId) -or
      [string]$app.$MatchBy -ine $ExpectedValue) {
    throw "The Graph application lookup for '$ExpectedValue' returned a different or incomplete identity."
  }
  return $app
}

function Select-MaesterLinkedPlan {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Payload,
    [Parameter(Mandatory)]$Site,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$EnvironmentName
  )

  $prefix = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/serverfarms/"
  $planId = [string]$Site.properties.serverFarmId
  if (-not $planId.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Site '$($Site.name)' has no hosting plan in the selected deployment scope."
  }
  $planName = $planId.Substring($prefix.Length)
  return Select-ExactMaesterResource -Payload $Payload -Name $planName `
    -ProviderType 'Microsoft.Web/serverfarms' -SubscriptionId $SubscriptionId `
    -ResourceGroupName $ResourceGroupName -EnvironmentName $EnvironmentName -SolutionName 'function-app'
}

function Assert-MaesterAzdSelectedEnvironment {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$EnvironmentName,
    [Parameter(Mandatory)][string]$ProjectRoot,
    [string]$SubscriptionId = '',
    [string]$TenantId = ''
  )

  $defaultJson = & azd env get-values --output json --cwd $ProjectRoot 2>$null
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($defaultJson | Out-String))) {
    throw 'The currently selected azd environment could not be verified.'
  }
  try { $values = $defaultJson | ConvertFrom-Json -AsHashtable }
  catch { throw 'The currently selected azd environment returned invalid values.' }
  if ($null -eq $values -or
      [string]$values.AZURE_ENV_NAME -cne $EnvironmentName -or
      ($SubscriptionId -and [string]$values.AZURE_SUBSCRIPTION_ID -ine $SubscriptionId) -or
      ($TenantId -and [string]$values.AZURE_TENANT_ID -ine $TenantId)) {
    throw 'The currently selected azd environment does not match the deployment target.'
  }
  return $values
}

function Assert-MaesterAzdTarget {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$EnvironmentName,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$ProjectRoot
  )

  # Vendored helpers can still use the current selection; check it first.
  $defaultValues = Assert-MaesterAzdSelectedEnvironment -EnvironmentName $EnvironmentName `
    -ProjectRoot $ProjectRoot -SubscriptionId $SubscriptionId
  if ([string]$defaultValues.AZURE_RESOURCE_GROUP -ine $ResourceGroupName) {
    throw 'The currently selected azd environment does not match the deployment target scope.'
  }

  $json = & azd env get-values --output json -e $EnvironmentName --cwd $ProjectRoot 2>$null
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($json | Out-String))) {
    throw 'The selected azd environment could not be verified.'
  }
  try { $values = $json | ConvertFrom-Json -AsHashtable }
  catch { throw 'The selected azd environment returned invalid values.' }
  if ($null -eq $values -or
      [string]$values.AZURE_ENV_NAME -cne $EnvironmentName -or
      [string]$values.AZURE_SUBSCRIPTION_ID -ine $SubscriptionId -or
      [string]$values.AZURE_RESOURCE_GROUP -ine $ResourceGroupName) {
    throw 'The selected azd environment does not match the deployment target scope.'
  }
  return $values
}

function Set-MaesterAzdValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$EnvironmentName,
    [Parameter(Mandatory)][string]$ProjectRoot,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][AllowEmptyString()][string]$Value
  )

  & azd env set $Name $Value -e $EnvironmentName --cwd $ProjectRoot 1>$null 2>$null
  if ($LASTEXITCODE -ne 0) { throw "Failed to persist $Name to the selected azd environment." }
}

Export-ModuleMember -Function Select-ExactMaesterResource, Select-UniqueGraphApplication, Select-MaesterLinkedPlan, Assert-MaesterAzdSelectedEnvironment, Assert-MaesterAzdTarget, Set-MaesterAzdValue
