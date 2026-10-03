$global:tick = 0
$global:requestId = $null
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Microsoft.PowerShell.Core\Import-Module (Join-Path $root 'scripts/FunctionValidation.Core.psm1') -Force
function Import-Module { param($Name, [switch]$Force) }
function Get-Date {
  $global:tick++
  return ([datetime]'2026-10-03T00:00:00Z').AddSeconds(10 * $global:tick)
}
function Start-Sleep { param($Seconds) }
function Get-AzCliSubscriptionContext { return @{ tenantId = '22222222-2222-4222-8222-222222222222' } }
function az {
  $global:LASTEXITCODE = 0
  return 'synthetic-token'
}
function Throw-Http404 {
  $errorValue = [Exception]::new('simulated 404')
  $errorValue | Add-Member -MemberType NoteProperty -Name Response -Value ([pscustomobject]@{ StatusCode = 404 })
  throw $errorValue
}
function Invoke-WebRequest {
  param($Uri, $Method, $Headers, $Body, [switch]$UseBasicParsing, $ErrorAction)
  if ($Method -eq 'HEAD') {
    if ($env:VALIDATION_TEST_MODE -eq 'collision') { return [pscustomobject]@{ StatusCode = 200 } }
    Throw-Http404
  }
  if ($Method -eq 'POST' -and $Uri -like '*/admin/functions/MaesterValidationTrigger') {
    $global:requestId = ($Body | ConvertFrom-Json).input
    $parsed = [guid]::Empty
    if (-not [guid]::TryParse($global:requestId, [ref]$parsed)) { throw 'No GUID trigger input.' }
    return [pscustomobject]@{ StatusCode = 202 }
  }
  throw "Unexpected web request: $Method $Uri"
}
function Invoke-RestMethod {
  param($Uri, $Method, $Headers, $Body, $ContentType, $ErrorAction)
  if ($Uri -match '/listkeys\?api-version=') {
    return [pscustomobject]@{ masterKey = 'synthetic-master-key' }
  }
  if ($Uri -match '/providers/Microsoft.Web/sites/func-test\?api-version=') {
    return [pscustomobject]@{ name = 'func-test'; kind = 'functionapp,linux' }
  }
  if ($Uri -match '/providers/Microsoft.Storage/storageAccounts/sttest\?api-version=') {
    return [pscustomobject]@{ name = 'sttest' }
  }
  if ($Uri -like 'https://sttest.blob.core.windows.net/validation/*.json') {
    if ($env:VALIDATION_TEST_MODE -eq 'missing') { Throw-Http404 }
    $receiptId = if ($env:VALIDATION_TEST_MODE -eq 'stale') { [guid]::NewGuid().ToString('D') } else { $global:requestId }
    $state = if ($env:VALIDATION_TEST_MODE -eq 'failed') { 'Failed' } else { 'Succeeded' }
    return [pscustomobject]@{
      schemaVersion = 1
      validationId = $receiptId
      invocationId = [guid]::NewGuid().ToString('D')
      status = $state
    }
  }
  throw "Unexpected REST request: $Method $Uri"
}
$PSStyle.OutputRendering = 'PlainText'
try {
  $result = & (Join-Path $root 'scripts/Invoke-FunctionValidation.ps1') `
    -SubscriptionId '11111111-1111-4111-8111-111111111111' `
    -ResourceGroupName 'rg-test' -FunctionAppName 'func-test' -StorageAccountName 'sttest' `
    -TimeoutMinutes 1 -PassThru
  $result | ConvertTo-Json -Compress
  exit 0
}
catch {
  Write-Error $_.Exception.Message
  exit 1
}
