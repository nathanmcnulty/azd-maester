# Azure Functions profile.ps1
#
# This profile is loaded when the Azure Functions host starts.
# Managed dependencies are installed after this profile runs;
# modules like Az.Accounts are imported automatically.

# Authenticate with the Function App managed identity.
# IDENTITY_ENDPOINT is the modern env var; MSI_SECRET is the legacy fallback.
if ($env:IDENTITY_ENDPOINT -or $env:MSI_SECRET) {
    Disable-AzContextAutosave -Scope Process | Out-Null
    Connect-AzAccount -Identity | Out-Null
}
