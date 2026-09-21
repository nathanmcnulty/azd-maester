@{
    RootModule = 'Azd.DeploymentValidation.psm1'
    ModuleVersion = '1.1.1'
    GUID = '55b77c65-9a89-4b7f-9ed0-0c0d9a33e9d9'
    Author = 'Nathan McNulty'
    CompanyName = 'Community'
    Copyright = 'Released into the public domain under the Unlicense.'
    Description = 'Structured deployment validation with defense-in-depth report redaction for azd solutions.'
    PowerShellVersion = '7.2'
    FunctionsToExport = @(
        'Assert-AzdValidationSucceeded',
        'ConvertTo-AzdSafeData',
        'Invoke-AzdValidationSet',
        'Invoke-AzdValidationCheck',
        'New-AzdCheckFailure',
        'New-AzdCheckOutcome',
        'New-AzdValidationCheckDefinition',
        'New-AzdValidationReport',
        'Write-AzdValidationReport',
        'Write-AzdValidationSummary'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('azd', 'Azure', 'validation')
            ProjectUri = 'https://github.com/nathanmcnulty/azd-reference'
            LicenseUri = 'https://unlicense.org/'
        }
    }
}
