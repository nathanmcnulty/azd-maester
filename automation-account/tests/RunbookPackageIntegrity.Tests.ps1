Describe 'Automation runbook package integrity' {
  BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $runbookPath = Join-Path $repoRoot 'scripts/Invoke-MaesterAutomationRunbook.ps1'
    $runbookText = Get-Content -LiteralPath $runbookPath -Raw
    $infraText = Get-Content -LiteralPath (Join-Path $repoRoot 'infra/main.bicep') -Raw
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($runbookPath, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'Runbook has PowerShell parse errors.' }
    $functionAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Import-LockedRuntimeModule' }, $true)
    if (-not $functionAst) { throw 'Runbook package verifier was not found.' }
    . ([scriptblock]::Create($functionAst.Extent.Text))
  }

  It 'keeps runbook byte locks aligned with every infrastructure package import' {
    $matches = [regex]::Matches($infraText, "uri: 'https://www.powershellgallery.com/api/v2/package/(?<name>[A-Za-z0-9.]+)/(?<version>[0-9.]+)'\s+contentHash: \{ algorithm: 'sha256', value: '(?<hash>[A-F0-9]{64})' \}")
    $matches.Count | Should -Be 9
    foreach ($package in $matches) {
      $name = [regex]::Escape($package.Groups['name'].Value)
      $version = [regex]::Escape($package.Groups['version'].Value)
      $hash = $package.Groups['hash'].Value
      $runbookText | Should -Match "'$name' = @\{ Version = '$version'; Sha256 = '$hash' \}"
    }
  }

  It 'imports a verified package and rejects changed bytes before module import' {
    $source = Join-Path $TestDrive 'source'
    $packages = Join-Path $TestDrive 'packages'
    $installed = Join-Path $TestDrive 'installed'
    New-Item -ItemType Directory -Path $source, $packages, $installed | Out-Null
    Set-Content -LiteralPath (Join-Path $source 'Example.psd1') -Value '@{ModuleVersion="1.0.0"; RootModule="Example.psm1"}'
    Set-Content -LiteralPath (Join-Path $source 'Example.psm1') -Value 'function Get-Example { 1 }; Export-ModuleMember -Function Get-Example'
    $package = Join-Path $packages 'Example.1.0.0.nupkg'
    Compress-Archive -Path (Join-Path $source '*') -DestinationPath $package
    $lock = @{ Example = @{ Version = '1.0.0'; Sha256 = (Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash } }
    Import-LockedRuntimeModule -Name Example -PackageLock $lock -DestinationRoot $installed -PackageDirectory $packages
    Get-Example | Should -Be 1
    (Get-Module Example).ModuleBase | Should -Be (Join-Path $installed 'Example/1.0.0')

    Add-Content -LiteralPath $package -Value 'changed'
    $tampered = Join-Path $TestDrive 'tampered'
    { Import-LockedRuntimeModule -Name Example -PackageLock $lock -DestinationRoot $tampered -PackageDirectory $packages } |
      Should -Throw '*failed SHA-256 verification*'
    Test-Path -LiteralPath (Join-Path $tampered 'Example') | Should -BeFalse
    Remove-Module Example -Force
  }

  It 'verifies optional modules before their connection attempts' {
    $runbookText | Should -Match 'if \(\$includeExchange\) \{[\s\S]*?Import-LockedRuntimeModule -Name ''ExchangeOnlineManagement'''
    $runbookText | Should -Match 'if \(\$includeTeams\) \{[\s\S]*?Import-LockedRuntimeModule -Name ''MicrosoftTeams'''
    $runbookText | Should -Not -Match 'Import-Module ExchangeOnlineManagement -Force|Import-Module MicrosoftTeams -Force'
  }
}
