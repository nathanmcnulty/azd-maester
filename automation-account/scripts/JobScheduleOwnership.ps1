function Test-MaesterGuid {
  param([string]$Value)
  $parsed = [guid]::Empty
  return [guid]::TryParse($Value, [ref]$parsed)
}

function Assert-MaesterOwnershipReceiptTarget {
  param(
    [Parameter(Mandatory = $true)][string]$ExpectedAccountId,
    [Parameter(Mandatory = $true)][string]$ExpectedPrincipalId,
    [Parameter(Mandatory = $true)][string]$ExpectedJobScheduleId,
    [Parameter(Mandatory = $true)]$Account,
    [Parameter(Mandatory = $true)]$JobSchedule
  )
  $liveJobScheduleId = [string]$JobSchedule.properties.jobScheduleId
  if ([string]::IsNullOrWhiteSpace($liveJobScheduleId)) { $liveJobScheduleId = [string]$JobSchedule.name }
  if (-not (Test-MaesterGuid -Value $ExpectedJobScheduleId) -or
      [string]$Account.id -ine $ExpectedAccountId -or
      [string]$Account.identity.principalId -ine $ExpectedPrincipalId -or
      $liveJobScheduleId -ine $ExpectedJobScheduleId -or
      [string]$JobSchedule.properties.schedule.name -ine 'maester-weekly-sunday' -or
      [string]$JobSchedule.properties.runbook.name -ine 'maester-runbook') {
    throw 'Provisioned Automation account or jobSchedule does not match the template ownership receipt.'
  }
}

function Resolve-MaesterJobScheduleOwnership {
  param(
    [Parameter(Mandatory = $true)][string]$ExpectedAccountId,
    [AllowNull()]$Account,
    [AllowNull()][object[]]$JobSchedules = @(),
    [string]$ReceiptAccountId = '',
    [string]$ReceiptPrincipalId = '',
    [string]$ReceiptJobScheduleId = '',
    [string]$AdoptAccountId = '',
    [string]$AdoptPrincipalId = '',
    [string]$AdoptJobScheduleId = ''
  )

  if ($null -eq $Account) {
    $priorBinding = @(@($ReceiptAccountId, $ReceiptPrincipalId, $ReceiptJobScheduleId,
      $AdoptAccountId, $AdoptPrincipalId, $AdoptJobScheduleId) |
      Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($priorBinding.Count -gt 0) {
      throw 'The prior Automation ownership receipt or adoption target has no matching live account; reconcile the exact target before redeployment.'
    }
    return [pscustomobject]@{ JobScheduleId = [guid]::NewGuid().ToString(); OwnedJobScheduleId = '' }
  }

  $liveAccountId = [string]$Account.id
  $livePrincipalId = [string]$Account.identity.principalId
  if ($liveAccountId -ine $ExpectedAccountId -or [string]::IsNullOrWhiteSpace($livePrincipalId)) {
    throw 'The live Automation account identity does not match the expected deployment target.'
  }

  $hasReceipt = -not [string]::IsNullOrWhiteSpace($ReceiptAccountId)
  $receiptParts = @(@($ReceiptAccountId, $ReceiptPrincipalId, $ReceiptJobScheduleId) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
  if ($receiptParts.Count -gt 0 -and $receiptParts.Count -lt 3) {
    throw 'The saved Automation ownership receipt is incomplete.'
  }
  if ($hasReceipt) {
    if ($ReceiptAccountId -ine $liveAccountId -or $ReceiptPrincipalId -ine $livePrincipalId -or
        -not (Test-MaesterGuid -Value $ReceiptJobScheduleId)) {
      throw 'The saved Automation ownership receipt does not match the live account identity or has no valid jobSchedule ID.'
    }
    $selectedId = $ReceiptJobScheduleId
  }
  else {
    if ($AdoptAccountId -ine $liveAccountId -or $AdoptPrincipalId -ine $livePrincipalId) {
      throw 'Existing Automation account has no matching ownership receipt. Explicit adoption of its account ID and principal ID is required before redeployment.'
    }
    $selectedId = $AdoptJobScheduleId
  }

  $owned = @()
  foreach ($jobSchedule in @($JobSchedules)) {
    if ($null -eq $jobSchedule) { continue }
    $id = [string]$jobSchedule.properties.jobScheduleId
    $nameId = [string]$jobSchedule.name
    if ([string]::IsNullOrWhiteSpace($id)) { $id = $nameId }
    if (-not [string]::IsNullOrWhiteSpace($nameId) -and $nameId -ine $id) {
      throw 'A live jobSchedule has inconsistent name and jobScheduleId values.'
    }
    if (-not (Test-MaesterGuid -Value $id)) {
      throw 'A live jobSchedule has no valid GUID. Refusing to change an ambiguous account.'
    }
    $scheduleName = [string]$jobSchedule.properties.schedule.name
    $runbookName = [string]$jobSchedule.properties.runbook.name
    if ($scheduleName -ieq 'maester-weekly-sunday' -and $runbookName -ine 'maester-runbook') {
      throw 'The template schedule name is linked to an unexpected runbook.'
    }
    if ($id -ieq $selectedId -and ($scheduleName -ine 'maester-weekly-sunday' -or $runbookName -ine 'maester-runbook')) {
      throw 'The recorded jobSchedule ID now belongs to a different schedule or runbook.'
    }
    if ($scheduleName -ieq 'maester-weekly-sunday' -and $runbookName -ieq 'maester-runbook') {
      $owned += $id
    }
  }

  if ($owned.Count -gt 1) { throw 'More than one live template jobSchedule exists; explicit reconciliation is required.' }
  if ($owned.Count -eq 1 -and [string]::IsNullOrWhiteSpace($selectedId)) {
    throw 'A live template jobSchedule requires its exact ID for explicit adoption.'
  }
  if ($owned.Count -eq 1 -and $owned[0] -ine $selectedId) {
    throw 'The live template jobSchedule ID differs from the saved receipt or explicit adoption ID.'
  }
  if (-not [string]::IsNullOrWhiteSpace($selectedId) -and -not (Test-MaesterGuid -Value $selectedId)) {
    throw 'The adopted jobSchedule ID must be a GUID.'
  }
  if ($owned.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($AdoptJobScheduleId) -and -not $hasReceipt) {
    throw 'The explicit adoption jobSchedule ID was not found in the live account.'
  }

  return [pscustomobject]@{
    JobScheduleId = if ([string]::IsNullOrWhiteSpace($selectedId)) { [guid]::NewGuid().ToString() } else { $selectedId }
    OwnedJobScheduleId = if ($owned.Count -eq 1) { $owned[0] } else { '' }
  }
}

function Assert-MaesterJobScheduleWriteTarget {
  param(
    [Parameter(Mandatory = $true)][string]$ExpectedAccountId,
    [Parameter(Mandatory = $true)][string]$ExpectedPrincipalId,
    [Parameter(Mandatory = $true)][string]$JobScheduleId,
    [Parameter(Mandatory = $true)]$Account,
    [AllowNull()][object[]]$JobSchedules = @(),
    [string]$ReceiptAccountId = '',
    [string]$ReceiptPrincipalId = '',
    [string]$ReceiptJobScheduleId = '',
    [string]$AdoptAccountId = '',
    [string]$AdoptPrincipalId = '',
    [string]$AdoptJobScheduleId = ''
  )

  if (-not (Test-MaesterGuid -Value $JobScheduleId) -or
      [string]$Account.id -ine $ExpectedAccountId -or
      [string]$Account.identity.principalId -ine $ExpectedPrincipalId) {
    throw 'The selected jobSchedule or Automation account identity does not match the deployment target.'
  }
  $receiptParts = @(@($ReceiptAccountId, $ReceiptPrincipalId, $ReceiptJobScheduleId) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
  if ($receiptParts.Count -gt 0 -and $receiptParts.Count -lt 3) { throw 'The saved Automation ownership receipt is incomplete.' }
  if ($receiptParts.Count -eq 3 -and
      ($ReceiptAccountId -ine $ExpectedAccountId -or $ReceiptPrincipalId -ine $ExpectedPrincipalId -or $ReceiptJobScheduleId -ine $JobScheduleId)) {
    throw 'The saved Automation ownership receipt differs from the selected jobSchedule.'
  }
  $adoptParts = @(@($AdoptAccountId, $AdoptPrincipalId, $AdoptJobScheduleId) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
  if ($receiptParts.Count -eq 0 -and $adoptParts.Count -gt 0 -and
      ($adoptParts.Count -ne 3 -or $AdoptAccountId -ine $ExpectedAccountId -or
       $AdoptPrincipalId -ine $ExpectedPrincipalId -or $AdoptJobScheduleId -ine $JobScheduleId)) {
    throw 'The explicit Automation adoption target differs from the selected jobSchedule.'
  }
  $matchingTemplateIds = @()
  foreach ($item in @($JobSchedules)) {
    if ($null -eq $item) { throw 'Automation jobSchedule inventory contains an empty record.' }
    $id = [string]$item.properties.jobScheduleId
    if ([string]::IsNullOrWhiteSpace($id)) { $id = [string]$item.name }
    if (-not (Test-MaesterGuid -Value $id) -or
        (-not [string]::IsNullOrWhiteSpace([string]$item.name) -and [string]$item.name -ine $id)) {
      throw 'Automation jobSchedule inventory contains an ambiguous ID.'
    }
    $isTemplate = [string]$item.properties.schedule.name -ieq 'maester-weekly-sunday' -and
      [string]$item.properties.runbook.name -ieq 'maester-runbook'
    if ([string]$item.properties.schedule.name -ieq 'maester-weekly-sunday' -and -not $isTemplate) {
      throw 'The template schedule name is linked to an unexpected runbook.'
    }
    if ($id -ieq $JobScheduleId -and -not $isTemplate) {
      throw 'The selected jobSchedule ID belongs to another association.'
    }
    if ($isTemplate) { $matchingTemplateIds += $id }
  }
  if ($matchingTemplateIds.Count -gt 1 -or
      ($matchingTemplateIds.Count -eq 1 -and $matchingTemplateIds[0] -ine $JobScheduleId)) {
    throw 'The template jobSchedule association is ambiguous or differs from the selected ID.'
  }
  if ($matchingTemplateIds.Count -eq 1 -and $receiptParts.Count -eq 0 -and $adoptParts.Count -eq 0) {
    throw 'An existing template jobSchedule requires an ownership receipt or explicit adoption.'
  }
}
