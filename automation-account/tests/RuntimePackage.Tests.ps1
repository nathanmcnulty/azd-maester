Describe 'Automation runtime package reproducibility' {
  It 'pins every deployed package to the validated runtime version' {
    $bicepLines = Get-Content (Join-Path $PSScriptRoot '..\infra\main.bicep')
    $expected = @{
      'Az.Accounts' = '5.5.3'
      'Maester' = '2.2.0'
      'Pester' = '6.2.0'
      'NuGet' = '1.3.3'
      'PackageManagement' = '1.4.8.1'
      'PowerShellGet' = '2.2.5'
      'Microsoft.Graph.Authentication' = '2.41.0'
      'ExchangeOnlineManagement' = '3.10.1'
      'MicrosoftTeams' = '8.0.0'
    }
    foreach ($name in $expected.Keys) {
      ($bicepLines -match "/$([regex]::Escape($expected[$name]))'").Count | Should -BeGreaterThan 0
    }
  }

  It 'requires a SHA-256 content hash for each runtime package resource' {
    $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../infra/main.bicep') -Raw
    $resources = [regex]::Matches($text, '(?s)resource runtimePackage\w+ .*?= (?:if \([^)]*\) )?\{.*?contentLink:\s*\{(?<link>.*?)\}\s*\}')
    $resources.Count | Should -Be 9
    foreach ($resource in $resources) {
      $link = $resource.Groups['link'].Value
      $link | Should -Match "uri:\s*'https://www\.powershellgallery\.com/api/v2/package/[A-Za-z0-9.]+/\d+(?:\.\d+){1,3}'"
      $link | Should -Match "contentHash:\s*\{\s*algorithm:\s*'sha256',\s*value:\s*'[A-F0-9]{64}'"
    }
  }

  It 'gates optional Exchange and Teams package resources and dependencies' {
    $bicepLines = Get-Content (Join-Path $PSScriptRoot '..\infra\main.bicep')
    @($bicepLines | Where-Object { $_ -match "resource runtimePackageExchangeOnlineManagement.*= if \(includeExchange\)" }).Count | Should -Be 1
    @($bicepLines | Where-Object { $_ -match "resource runtimePackageMicrosoftTeams.*= if \(includeTeams\)" }).Count | Should -Be 1
    @($bicepLines | Where-Object { $_ -match 'runtimePackageExchangeOnlineManagement' }).Count | Should -Be 2
    @($bicepLines | Where-Object { $_ -match 'runtimePackageMicrosoftTeams' }).Count | Should -Be 2
  }

  It 'never links the pinned seed runbook to a schedule during infrastructure provisioning' {
    $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../infra/main.bicep') -Raw
    $text | Should -Not -Match 'resource jobSchedule '
    $text | Should -Match "raw.githubusercontent.com/maester365/maester/[0-9a-f]{40}/powershell/public/Invoke-Maester.ps1"
    $text | Should -Match "publishContentLink:\s*\{[^}]*contentHash:\s*\{\s*algorithm:\s*'sha256',\s*value:\s*'[A-F0-9]{64}'"
    $setup = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../scripts/Setup-PostDeploy.ps1') -Raw
    $setup.IndexOf('if (-not $publishedLocalRunbook)') | Should -BeLessThan $setup.IndexOf('Invoke-RestMethod -Method PUT -Uri "https://management.azure.com$jobScheduleUri"')
  }
}
