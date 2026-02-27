[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$TenantId,

  [Parameter(Mandatory = $false)]
  [string]$EnvironmentName,

  [Parameter(Mandatory = $false)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $false)]
  [string]$SecurityGroupObjectId,

  [Parameter(Mandatory = $false)]
  [string]$SecurityGroupDisplayName,

  [Parameter(Mandatory = $false)]
  [ValidateSet('Minimal', 'Extended')]
  [string]$PermissionProfile = 'Extended'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-EnvValue {
  param(
    [Parameter(Mandatory = $true)]
    $Lines,

    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  if ($Lines -is [hashtable]) {
    if ($Lines.ContainsKey($Name)) {
      return [string]$Lines[$Name]
    }
    return $null
  }

  foreach ($line in @($Lines)) {
    if ($line -like "$Name=*") {
      return $line.Split('=', 2)[1].Trim('"')
    }
  }

  return $null
}

$envLines = @{}
try {
  $envLines = (& azd env get-values --output json 2>$null | ConvertFrom-Json -AsHashtable)
}
catch {
  $envLines = @{}
}

if (-not $SubscriptionId) {
  $SubscriptionId = if ($env:AZURE_SUBSCRIPTION_ID) { $env:AZURE_SUBSCRIPTION_ID } else { Get-EnvValue -Lines $envLines -Name 'AZURE_SUBSCRIPTION_ID' }
}
if (-not $TenantId) {
  $TenantId = if ($env:AZURE_TENANT_ID) { $env:AZURE_TENANT_ID } else { Get-EnvValue -Lines $envLines -Name 'AZURE_TENANT_ID' }
}
if (-not $EnvironmentName) {
  $EnvironmentName = if ($env:AZURE_ENV_NAME) { $env:AZURE_ENV_NAME } else { Get-EnvValue -Lines $envLines -Name 'AZURE_ENV_NAME' }
  if ([string]::IsNullOrWhiteSpace($EnvironmentName)) {
    $EnvironmentName = 'dev'
  }
}
if (-not $ResourceGroupName) {
  $ResourceGroupName = if ($env:AZURE_RESOURCE_GROUP) { $env:AZURE_RESOURCE_GROUP } else { Get-EnvValue -Lines $envLines -Name 'AZURE_RESOURCE_GROUP' }
  if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
    $ResourceGroupName = "rg-$EnvironmentName"
  }
}
if (-not $SecurityGroupObjectId) {
  if ($env:SECURITY_GROUP_OBJECT_ID) {
    $SecurityGroupObjectId = $env:SECURITY_GROUP_OBJECT_ID
  }
  elseif ($env:EASY_AUTH_SECURITY_GROUP_OBJECT_ID) {
    $SecurityGroupObjectId = $env:EASY_AUTH_SECURITY_GROUP_OBJECT_ID
  }
  else {
    $SecurityGroupObjectId = Get-EnvValue -Lines $envLines -Name 'SECURITY_GROUP_OBJECT_ID'
    if (-not $SecurityGroupObjectId) {
      $SecurityGroupObjectId = Get-EnvValue -Lines $envLines -Name 'EASY_AUTH_SECURITY_GROUP_OBJECT_ID'
    }
  }
}
if (-not $SecurityGroupDisplayName) {
  if ($env:SECURITY_GROUP_DISPLAY_NAME) {
    $SecurityGroupDisplayName = $env:SECURITY_GROUP_DISPLAY_NAME
  }
  else {
    $SecurityGroupDisplayName = Get-EnvValue -Lines $envLines -Name 'SECURITY_GROUP_DISPLAY_NAME'
  }
}
if (-not $PSBoundParameters.ContainsKey('PermissionProfile') -and $env:PERMISSION_PROFILE) {
  $PermissionProfile = $env:PERMISSION_PROFILE
}

Write-Host 'Running postprovision setup...'

$setupParams = @{
  SubscriptionId    = $SubscriptionId
  EnvironmentName   = $EnvironmentName
  ResourceGroupName = $ResourceGroupName
  PermissionProfile = $PermissionProfile
}
if ($TenantId) {
  $setupParams['TenantId'] = $TenantId
}
if ($SecurityGroupObjectId) {
  $setupParams['SecurityGroupObjectId'] = $SecurityGroupObjectId
}
if ($SecurityGroupDisplayName) {
  $setupParams['SecurityGroupDisplayName'] = $SecurityGroupDisplayName
}

& "$PSScriptRoot\Setup-PostDeploy.ps1" @setupParams

Write-Host 'azd postprovision completed successfully.'
