#Requires -Version 7.6
Describe 'Automation PowerShell 7.6 / .NET 10 baseline' {
    BeforeAll {
        $repoRoot = Join-Path $PSScriptRoot '..'
        $bicep = Get-Content (Join-Path $repoRoot 'infra/main.bicep') -Raw
    }

    It 'requires PowerShell 7.6 at maintained Automation entry points' {
        foreach ($entryPoint in Get-ChildItem (Join-Path $repoRoot 'scripts') -File -Filter '*.ps1') {
            (Get-Content $entryPoint.FullName -TotalCount 1) | Should -Be '#Requires -Version 7.6' -Because $entryPoint.Name
        }
    }

    It 'uses a distinct 7.6 runtime environment and binds the runbook to it' {
        $bicep | Should -Match "var runtimeEnvironmentName = 'PowerShell-76-Maester'"
        $bicep | Should -Match "resource runtime76 '[^']+/runtimeEnvironments@[^']+' = \{[\s\S]*?runtime: \{\s*language: 'PowerShell'\s*version: '7\.6'"
        $bicep | Should -Match 'runtimeEnvironment: runtime76\.name'
        $bicep | Should -Not -Match 'runtime74|PowerShell-74-Maester|version: ''7\.4'''
        ([regex]::Matches($bicep, 'parent: runtime76')).Count | Should -Be 9
    }

    It 'advertises the supported baseline without rewriting historical package observations' {
        $readme = Get-Content (Join-Path $repoRoot 'README.md') -Raw
        $packages = Get-Content (Join-Path $repoRoot 'docs/runtime-package-pins.md') -Raw
        $readme | Should -Match 'PowerShell 7\.6 runtime'
        $packages | Should -Match 'Versions were observed in the succeeded `PowerShell-74-Maester`'
    }
}
