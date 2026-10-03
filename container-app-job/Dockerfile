FROM mcr.microsoft.com/powershell:lts-mariner-2.0@sha256:77d815b197b36e1f9fa454effa4edd405ce793ad5c16e57489316b9637879951

SHELL ["pwsh", "-Command"]

# Download exact package bytes and verify SHA-256 before extraction.
COPY runtime-packages.lock.json /tmp/runtime-packages.lock.json
COPY scripts/Install-LockedModules.ps1 /tmp/Install-LockedModules.ps1
RUN pwsh -NoProfile -File /tmp/Install-LockedModules.ps1 -LockPath /tmp/runtime-packages.lock.json

# Runner script is mounted via Azure Files volume at /mnt/scripts
# This image only pre-installs modules for faster startup
