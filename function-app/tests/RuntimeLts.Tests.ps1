#Requires -Version 7.6
BeforeAll {
  $root = Split-Path $PSScriptRoot -Parent
  $template = Get-Content (Join-Path $root 'infra/main.json') -Raw | ConvertFrom-Json -AsHashtable
  $bicep = Get-Content (Join-Path $root 'infra/main.bicep') -Raw
}

Describe 'PowerShell 7.6 Function hosting contract' {
  It 'requires PowerShell 7.6 at maintained setup, packaging and worker entry points' {
    $entryPoints = @(Get-ChildItem (Join-Path $root 'scripts') -File -Filter '*.ps1') + @(Get-ChildItem (Join-Path $root 'src') -Recurse -File -Filter '*.ps1')
    foreach ($entryPoint in $entryPoints) {
      (Get-Content $entryPoint.FullName -TotalCount 1) | Should -Be '#Requires -Version 7.6' -Because $entryPoint.Name
    }
  }

  It 'supports exactly Flex Consumption and App Service Basic, defaulting to Flex' {
    @($template.parameters.functionAppPlan.allowedValues).Count | Should -Be 2
    @($template.parameters.functionAppPlan.allowedValues) | Should -Contain 'FC1'
    @($template.parameters.functionAppPlan.allowedValues) | Should -Contain 'B1'
    $template.parameters.functionAppPlan.defaultValue | Should -Be 'FC1'
    $template.variables.isFlexConsumption | Should -Be "[equals(parameters('functionAppPlan'), 'FC1')]"
    $template.variables.isDedicatedPlan | Should -Be "[equals(parameters('functionAppPlan'), 'B1')]"
    $plan = @($template.resources | Where-Object type -eq 'Microsoft.Web/serverfarms')[0]
    $plan.sku | Should -Be "[if(variables('isFlexConsumption'), createObject('name', 'FC1', 'tier', 'FlexConsumption'), createObject('name', parameters('functionAppPlan'), 'tier', 'Basic'))]"
    ($template | ConvertTo-Json -Depth 100) | Should -Match "'alwaysOn', variables\('isDedicatedPlan'\)"
  }

  It 'selects PowerShell 7.6 for both supported plans without an Azure Files content share' {
    $bicep | Should -Match "linuxFxVersion: 'PowerShell\|7\.6'"
    $bicep | Should -Match "name: 'powershell'\s+version: '7\.6'"
    $templateJson = $template | ConvertTo-Json -Depth 100
    $templateJson | Should -Not -Match 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING|WEBSITE_CONTENTSHARE|isConsumptionPlan|functionAppConsumptionAppSettings|PowerShell\|7\.4'
    $bicep | Should -Match 'appSettings: functionAppBaseAppSettings'
    $templateJson | Should -Match "PowerShell\|7\.6"
    $templateJson | Should -Match "'name', 'powershell', 'version', '7\.6'"
  }

  It 'accepts the same supported plans at every setup and packaging entry point' {
    foreach ($script in 'Setup-PostDeploy.ps1', 'Deploy-FunctionCode.ps1') {
      $tokens = $null; $errors = $null
      $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root "scripts/$script"), [ref]$tokens, [ref]$errors)
      $errors.Count | Should -Be 0
      $plan = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Plan' })[0]
      $allowed = @($plan.Attributes | Where-Object { $_.TypeName.FullName -eq 'ValidateSet' })[0]
      @($allowed.PositionalArguments.Value).Count | Should -Be 2
      @($allowed.PositionalArguments.Value) | Should -Contain 'FC1'
      @($allowed.PositionalArguments.Value) | Should -Contain 'B1'
    }
  }

  It 'uses the shared 30-minute host timeout without plan-specific rewriting' {
    $hostConfig = Get-Content (Join-Path $root 'src/host.json') -Raw | ConvertFrom-Json
    $hostConfig.functionTimeout | Should -Be '00:30:00'
    $hostConfig.managedDependency.enabled | Should -BeFalse
    $packager = Get-Content (Join-Path $root 'scripts/Deploy-FunctionCode.ps1') -Raw
    $packager | Should -Not -Match '\.functionTimeout\s*=|switch\s*\(\$Plan\)'
  }
}
