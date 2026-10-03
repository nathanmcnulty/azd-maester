[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$LockPath,
  [string]$DestinationRoot = '/usr/local/share/powershell/Modules',
  [string]$PackageDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json
if ($lock.schemaVersion -ne 1 -or @($lock.packages).Count -eq 0) { throw 'Invalid module package lock.' }
foreach ($package in $lock.packages) {
  $name = [string]$package.name
  $version = [string]$package.version
  $expectedHash = [string]$package.sha256
  if ($name -notmatch '^[A-Za-z][A-Za-z0-9.-]*$' -or $version -notmatch '^\d+(\.\d+){1,3}$' -or $expectedHash -notmatch '^[A-Fa-f0-9]{64}$') {
    throw "Invalid lock entry for '$name'."
  }
  $packagePath = if ($PackageDirectory) {
    Join-Path $PackageDirectory "$name.$version.nupkg"
  } else {
    Join-Path ([IO.Path]::GetTempPath()) "$name.$version.nupkg"
  }
  if (-not $PackageDirectory) {
    $uri = "https://www.powershellgallery.com/api/v2/package/$name/$version"
    Invoke-WebRequest -Uri $uri -OutFile $packagePath -ErrorAction Stop
  }
  if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) { throw "Locked package '$name/$version' is missing." }
  $actualHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash
  if ($actualHash -ne $expectedHash) { throw "Locked package '$name/$version' failed SHA-256 verification." }

  $target = Join-Path (Join-Path $DestinationRoot $name) $version
  if (Test-Path -LiteralPath $target) { throw "Destination already contains '$name/$version'." }
  New-Item -ItemType Directory -Path $target -Force | Out-Null
  try {
    [IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $target)
    if (-not (Test-Path -LiteralPath (Join-Path $target "$name.psd1") -PathType Leaf)) {
      throw "Locked package '$name/$version' has no expected module manifest."
    }
  }
  catch {
    Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
    throw
  }
  if (-not $PackageDirectory) { Remove-Item -LiteralPath $packagePath -Force }
  Write-Host "Verified and installed $name/$version."
}
