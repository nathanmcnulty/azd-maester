FROM mcr.microsoft.com/powershell:lts-mariner-2.0

SHELL ["pwsh", "-Command"]

# Trust PSGallery and install required modules for faster container startup
RUN Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
RUN Install-Module -Name Az.Accounts -Force -Scope AllUsers
RUN Install-Module -Name Microsoft.Graph.Authentication -Force -Scope AllUsers
RUN Install-Module -Name Maester -Force -Scope AllUsers
RUN Install-Module -Name Pester -Force -Scope AllUsers
RUN Install-Module -Name ExchangeOnlineManagement -Force -Scope AllUsers
RUN Install-Module -Name MicrosoftTeams -Force -Scope AllUsers

# Runner script is mounted via Azure Files volume at /mnt/scripts
# This image only pre-installs modules for faster startup
