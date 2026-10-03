Describe 'Azure DevOps runtime package integrity' {
  BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $installer = Join-Path $repoRoot 'scripts/Install-LockedModules.ps1'
    $lock = Get-Content -LiteralPath (Join-Path $repoRoot 'runtime-packages.lock.json') -Raw | ConvertFrom-Json
  }

  It 'locks each required and optional module to one exact version and SHA-256' {
    $required = @('Az.Accounts', 'Az.Storage', 'Az.Websites', 'Microsoft.Graph.Authentication',
      'Maester', 'Pester', 'NuGet', 'PackageManagement', 'PowerShellGet',
      'ExchangeOnlineManagement', 'MicrosoftTeams')
    @($lock.packages.name | Sort-Object -Unique).Count | Should -Be $required.Count
    foreach ($name in $required) {
      @($lock.packages | Where-Object name -EQ $name).Count | Should -Be 1
    }
    foreach ($package in $lock.packages) {
      $package.version | Should -Match '^\d+(\.\d+){1,3}$'
      $package.sha256 | Should -Match '^[A-F0-9]{64}$'
    }
  }

  It 'rejects changed package bytes before extracting the module' {
    $source = Join-Path $TestDrive 'source'
    $packages = Join-Path $TestDrive 'packages'
    $installed = Join-Path $TestDrive 'installed'
    New-Item -ItemType Directory -Path $source, $packages | Out-Null
    Set-Content -LiteralPath (Join-Path $source 'Example.psd1') -Value '@{ModuleVersion="1.0.0"; RootModule="Example.psm1"}'
    Set-Content -LiteralPath (Join-Path $source 'Example.psm1') -Value 'function Get-Example { 1 }'
    $package = Join-Path $packages 'Example.1.0.0.nupkg'
    Compress-Archive -Path (Join-Path $source '*') -DestinationPath $package
    $hash = (Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash
    $lockPath = Join-Path $TestDrive 'lock.json'
    @{ schemaVersion = 1; packages = @(@{ name = 'Example'; version = '1.0.0'; sha256 = $hash }) } |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $lockPath

    & $installer -LockPath $lockPath -PackageDirectory $packages -DestinationRoot $installed
    Test-Path -LiteralPath (Join-Path $installed 'Example/1.0.0/Example.psd1') | Should -BeTrue

    Add-Content -LiteralPath $package -Value 'changed'
    $tampered = Join-Path $TestDrive 'tampered'
    { & $installer -LockPath $lockPath -PackageDirectory $packages -DestinationRoot $tampered } |
      Should -Throw '*failed SHA-256 verification*'
    Test-Path -LiteralPath (Join-Path $tampered 'Example') | Should -BeFalse
  }

  It 'ships the installer and lock with the pipeline runner using workload identity' {
    $setup = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts/Setup-PostDeploy.ps1') -Raw
    $runner = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts/Invoke-MaesterAzureDevOpsRun.ps1') -Raw
    $pipeline = Get-Content -LiteralPath (Join-Path $repoRoot 'pipelines/template-maester.yml') -Raw
    $setup | Should -Match "Path = 'scripts/Install-LockedModules.ps1'"
    $setup | Should -Match "Path = 'runtime-packages.lock.json'"
    $runner | Should -Match 'Install-LockedModules.ps1'
    $runner | Should -Match '-FederatedToken \$env:idToken'
    $pipeline | Should -Match 'AzureCLI@2'
    $pipeline | Should -Match 'addSpnToEnvironment: true'
  }
}
