Describe 'Container runtime package integrity' {
  BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $installer = Join-Path $repoRoot 'scripts/Install-LockedModules.ps1'
    $lock = Get-Content -LiteralPath (Join-Path $repoRoot 'runtime-packages.lock.json') -Raw | ConvertFrom-Json
    $dockerfile = Get-Content -LiteralPath (Join-Path $repoRoot 'Dockerfile') -Raw
    $infra = Get-Content -LiteralPath (Join-Path $repoRoot 'infra/main.bicep') -Raw
  }

  It 'locks every module to an exact version and SHA-256 package digest' {
    @($lock.packages).Count | Should -BeGreaterThan 6
    @($lock.packages.name | Sort-Object -Unique).Count | Should -Be @($lock.packages).Count
    foreach ($package in $lock.packages) {
      $package.version | Should -Match '^\d+(\.\d+){1,3}$'
      $package.sha256 | Should -Match '^[A-F0-9]{64}$'
    }
    $dockerfile | Should -Match 'FROM mcr\.microsoft\.com/powershell:[^\s]+@sha256:[a-f0-9]{64}'
    $infra | Should -Match 'mcr\.microsoft\.com/powershell:[^\s\x27]+@sha256:[a-f0-9]{64}'
  }

  It 'rejects changed package bytes before extracting any module files' {
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

    $tampered = Join-Path $TestDrive 'tampered'
    Add-Content -LiteralPath $package -Value 'changed'
    { & $installer -LockPath $lockPath -PackageDirectory $packages -DestinationRoot $tampered } |
      Should -Throw '*failed SHA-256 verification*'
    Test-Path -LiteralPath (Join-Path $tampered 'Example') | Should -BeFalse
  }
}
