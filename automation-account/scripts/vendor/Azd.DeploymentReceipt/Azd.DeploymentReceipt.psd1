@{
    RootModule = 'Azd.DeploymentReceipt.psm1'
    ModuleVersion = '0.2.1'
    GUID = 'a5137cb8-7f77-4584-9d8c-a7f9eb9a3fb5'
    Author = 'Nathan McNulty'
    CompanyName = 'Community'
    Copyright = 'Released into the public domain under the Unlicense.'
    Description = 'Schema-validated, repository-relative deployment receipt writing for azd solutions.'
    PowerShellVersion = '7.2'
    FunctionsToExport = @(
        'New-AzdDeploymentReceipt',
        'Write-AzdDeploymentReceipt'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('azd', 'Azure', 'deployment', 'receipt')
            ProjectUri = 'https://github.com/nathanmcnulty/azd-reference'
            LicenseUri = 'https://unlicense.org/'
        }
    }
}
