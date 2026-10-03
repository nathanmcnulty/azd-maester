BeforeAll {
  $repoRoot = Split-Path $PSScriptRoot -Parent
  $contracts = Get-Content -LiteralPath (Join-Path $repoRoot 'runtime-contracts.lock.json') -Raw | ConvertFrom-Json
}

Describe 'Independent legacy runtime contracts' {
  It 'records a reviewed source revision and every deployable variant' {
    $contracts.schemaVersion | Should -Be 1
    @($contracts.files.path | ForEach-Object { ($_ -split '/')[0] } | Sort-Object -Unique) |
      Should -Be @('automation-account', 'azure-devops', 'container-app-job', 'function-app')
    foreach ($file in $contracts.files) {
      $file.sourceCommit | Should -Match '^[a-f0-9]{40}$'
      $file.sourceSha256 | Should -Match '^[A-F0-9]{64}$'
      if (-not $file.sourceMatch) { $file.legacyReason | Should -Not -BeNullOrEmpty }
    }
    @($contracts.localFiles.path | ForEach-Object { ($_ -split '/')[0] } | Sort-Object -Unique) |
      Should -Be @('automation-account', 'azure-devops', 'container-app-job', 'function-app')
    foreach ($file in $contracts.localFiles) {
      $file.sha256 | Should -Match '^[A-F0-9]{64}$'
      $file.reason | Should -Not -BeNullOrEmpty
    }
  }

  It 'detects a source contract drift in any nested solution' {
    foreach ($file in $contracts.files) {
      $path = Join-Path $repoRoot $file.path
      Test-Path -LiteralPath $path -PathType Leaf | Should -BeTrue
      $content = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8).TrimStart([char]0xFEFF)
      $normalized = $content.Replace("`r`n", "`n").Replace("`r", "`n")
      $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($normalized)))
      $hash | Should -Be $file.sha256 -Because $file.path
      if ($file.sourceMatch) { $file.sha256 | Should -Be $file.sourceSha256 -Because $file.path }
    }
    foreach ($file in $contracts.localFiles) {
      $path = Join-Path $repoRoot $file.path
      Test-Path -LiteralPath $path -PathType Leaf | Should -BeTrue
      $content = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8).TrimStart([char]0xFEFF)
      $normalized = $content.Replace("`r`n", "`n").Replace("`r", "`n")
      $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($normalized)))
      $hash | Should -Be $file.sha256 -Because $file.path
    }
  }
}
