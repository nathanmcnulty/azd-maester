Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:TemplateId = 'maester-automation-account'
$script:TemplateVersion = '0.1.0'

function Get-MaesterGuiReceiptBinding {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][hashtable]$GuiEnvironment,
    [Parameter(Mandatory = $true)][string]$EnvironmentName,
    [Parameter(Mandatory = $true)][string]$AzureCloud,
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$SubscriptionId,
    [Parameter(Mandatory = $true)][string]$ResourceGroupName
  )

  $requiredNames = @(
    'AZD_GUI_PROJECT_ID',
    'AZD_GUI_ENVIRONMENT',
    'AZD_GUI_TEMPLATE_ID',
    'AZD_GUI_SOURCE_REVISION',
    'AZD_GUI_CONTRACT_DIGEST',
    'AZD_GUI_OPERATION_ID',
    'AZD_GUI_OPERATION_KIND'
  )
  $presentNames = @($requiredNames | Where-Object {
      $GuiEnvironment.ContainsKey($_) -and -not [string]::IsNullOrWhiteSpace([string]$GuiEnvironment[$_])
    })

  if ($presentNames.Count -eq 0) {
    return $null
  }
  if ($presentNames.Count -ne $requiredNames.Count) {
    throw 'The azd-gui evidence context is incomplete; refusing to emit a partially bound receipt.'
  }
  if ([string]$GuiEnvironment.AZD_GUI_ENVIRONMENT -ne $EnvironmentName) {
    throw 'The azd-gui evidence environment does not match the selected azd environment.'
  }
  if ([string]$GuiEnvironment.AZD_GUI_OPERATION_KIND -notin @('up', 'provision', 'deploy')) {
    throw 'The azd-gui operation kind cannot produce a resource-mutation receipt.'
  }

  return [ordered]@{
    project = [ordered]@{
      id = [string]$GuiEnvironment.AZD_GUI_PROJECT_ID
      environment = $EnvironmentName
    }
    target = [ordered]@{
      azureCloud = $AzureCloud
      tenantId = $TenantId
      subscriptionId = $SubscriptionId
      resourceGroup = $ResourceGroupName
    }
    source = [ordered]@{
      templateId = [string]$GuiEnvironment.AZD_GUI_TEMPLATE_ID
      revision = [string]$GuiEnvironment.AZD_GUI_SOURCE_REVISION
      contractDigest = [string]$GuiEnvironment.AZD_GUI_CONTRACT_DIGEST
    }
    operation = [ordered]@{
      id = [string]$GuiEnvironment.AZD_GUI_OPERATION_ID
      kind = [string]$GuiEnvironment.AZD_GUI_OPERATION_KIND
    }
  }
}

function Write-MaesterDeploymentEvidence {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][datetimeoffset]$ValidationStartedAt,
    [Parameter(Mandatory = $true)][object]$ValidationResult,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Resources,
    [Parameter(Mandatory = $true)][string]$EnvironmentName,
    [Parameter(Mandatory = $true)][string]$AzureCloud,
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$SubscriptionId,
    [Parameter(Mandatory = $true)][string]$ResourceGroupName,
    [Parameter(Mandatory = $true)][string]$AutomationAccountName,
    [hashtable]$GuiEnvironment = @{}
  )

  Import-Module (Join-Path $PSScriptRoot 'vendor\Azd.DeploymentValidation\Azd.DeploymentValidation.psd1') -Force -Global
  Import-Module (Join-Path $PSScriptRoot 'vendor\Azd.DeploymentReceipt\Azd.DeploymentReceipt.psd1') -Force -Global

  $automationResource = @($Resources | Where-Object { $_.type -eq 'Microsoft.Automation/automationAccounts' -and $_.name -eq $AutomationAccountName }) | Select-Object -First 1
  $storageResource = @($Resources | Where-Object { $_.type -eq 'Microsoft.Storage/storageAccounts' }) | Select-Object -First 1

  $definitions = @(
    New-AzdValidationCheckDefinition `
      -Id 'context.azure-target' `
      -Phase context `
      -Title 'Selected Azure target' `
      -Summary 'The validation used the selected tenant, subscription, and resource group.' `
      -Expected 'A complete selected Azure target.' `
      -Action ({ New-AzdCheckOutcome -Status pass -Summary 'The selected Azure target was used.' -Evidence @{ azureCloud = $AzureCloud } }.GetNewClosure())

    New-AzdValidationCheckDefinition `
      -Id 'infrastructure.automation-account' `
      -Phase infrastructure `
      -Title 'Automation Account' `
      -Summary 'The expected Automation Account exists.' `
      -Expected $AutomationAccountName `
      -Remediation 'Review the resource-group deployment and rerun provisioning.' `
      -DependsOn 'context.azure-target' `
      -Action ({
          if ($automationResource) {
            New-AzdCheckOutcome -Status pass -Summary 'The expected Automation Account exists.' -Actual $AutomationAccountName
          }
          else {
            New-AzdCheckFailure -Code 'automationAccountMissing' -Summary 'The expected Automation Account was not found.' -Expected $AutomationAccountName -Remediation 'Review the resource-group deployment and rerun provisioning.'
          }
        }.GetNewClosure())

    New-AzdValidationCheckDefinition `
      -Id 'infrastructure.storage-account' `
      -Phase infrastructure `
      -Title 'Report storage account' `
      -Summary 'A report storage account exists in the deployment resource group.' `
      -Expected 'One Microsoft.Storage/storageAccounts resource.' `
      -Remediation 'Review the storage deployment and rerun provisioning.' `
      -DependsOn 'context.azure-target' `
      -Action ({
          if ($storageResource) {
            New-AzdCheckOutcome -Status pass -Summary 'The report storage account exists.' -Evidence @{ resourceType = 'Microsoft.Storage/storageAccounts' }
          }
          else {
            New-AzdCheckFailure -Code 'storageAccountMissing' -Summary 'The report storage account was not found.' -Expected 'One Microsoft.Storage/storageAccounts resource.' -Remediation 'Review the storage deployment and rerun provisioning.'
          }
        }.GetNewClosure())

    New-AzdValidationCheckDefinition `
      -Id 'runtime.runbook-job' `
      -Phase runtime `
      -Title 'Maester validation runbook' `
      -Summary 'The validation runbook completed successfully.' `
      -Expected 'Completed' `
      -Remediation 'Review the Azure Automation job output, correct the failure, and rerun validation.' `
      -DependsOn 'infrastructure.automation-account' `
      -Action ({
          if ($ValidationResult.ValidationPassed -and $ValidationResult.FinalStatus -eq 'Completed') {
            New-AzdCheckOutcome -Status pass -Summary 'The validation runbook completed successfully.' -Actual 'Completed' -Evidence @{ jobId = [string]$ValidationResult.JobId }
          }
          else {
            New-AzdCheckFailure -Code 'runbookValidationFailed' -Summary 'The validation runbook did not complete successfully.' -Expected 'Completed' -Details @{ finalStatus = [string]$ValidationResult.FinalStatus } -Remediation 'Review the Azure Automation job output, correct the failure, and rerun validation.'
          }
        }.GetNewClosure())
  )

  $checks = @(Invoke-AzdValidationSet -Definitions $definitions)
  $report = New-AzdValidationReport `
    -TemplateName $script:TemplateId `
    -TemplateVersion $script:TemplateVersion `
    -Mode verify `
    -StartedAt $ValidationStartedAt `
    -Checks $checks `
    -Environment @{
      name = $EnvironmentName
      azureCloud = $AzureCloud
      tenantId = $TenantId
      subscriptionId = $SubscriptionId
      resourceGroup = $ResourceGroupName
    }
  $validationPath = Write-AzdValidationReport -Report $report -RepositoryRoot $RepositoryRoot -OutputPath 'reports/deployment-validation.json'

  $binding = Get-MaesterGuiReceiptBinding `
    -GuiEnvironment $GuiEnvironment `
    -EnvironmentName $EnvironmentName `
    -AzureCloud $AzureCloud `
    -TenantId $TenantId `
    -SubscriptionId $SubscriptionId `
    -ResourceGroupName $ResourceGroupName

  $receiptParameters = @{
    Template = $script:TemplateId
    TemplateVersion = $script:TemplateVersion
    Mode = 'enforce'
    Applied = 1
    Failed = if ($report.outcome -eq 'failed') { 1 } else { 0 }
    Artifacts = @($validationPath)
  }
  if ($binding) {
    $receiptParameters.EvidenceClass = 'resourceMutation'
    $receiptParameters.EvidenceBinding = $binding
    if ($report.outcome -eq 'failed') {
      $receiptParameters.ManagementNextActions = @(
        [ordered]@{ code = 'retryOperation'; owner = 'operator'; priority = 'required' }
      )
    }
  }
  $receipt = New-AzdDeploymentReceipt @receiptParameters
  $receiptPath = Write-AzdDeploymentReceipt -Receipt $receipt -RepositoryRoot $RepositoryRoot -OutputPath 'reports/deployment-receipt.json'

  Write-AzdValidationSummary -Report $report
  [pscustomobject]@{
    Report = $report
    Receipt = $receipt
    ValidationPath = $validationPath
    ReceiptPath = $receiptPath
  }
}

Export-ModuleMember -Function 'Get-MaesterGuiReceiptBinding', 'Write-MaesterDeploymentEvidence'
