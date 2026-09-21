Set-StrictMode -Version Latest

$script:DefaultOutputPath = 'reports/deployment-receipt.json'
$script:MaxReceiptBytes = 1024KB
$script:MaxCollectionItems = 500
$script:MaxTextLength = 4096
$script:SensitiveKeyPattern = '(?i)(secret|password|token|credential|authorization|connectionstring|callback|(?:client|access|account|host|shared)key|(?:^|[._-])sig(?:$|[._-]))'
$script:SensitiveValuePattern = '(?i)(bearer\s+\S+|(?:accountkey|sharedaccesssignature|clientsecret|password)\s*=|[?&](?:sig|token|secret|password|key)=)'

function Test-AzdReceiptReparsePoint {
    param([Parameter(Mandatory)][string] $Path)

    (Get-Item -LiteralPath $Path -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint
}

function Assert-AzdReceiptText {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string] $Value,
        [Parameter(Mandatory)][string] $Label,
        [int] $MaximumLength = $script:MaxTextLength
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt $MaximumLength -or $Value -match '[\x00-\x1F]') {
        throw "$Label must be nonempty, bounded, and free of control characters."
    }
    if ($Value -match $script:SensitiveValuePattern -or $Value -match '(?i)https?://[^\s]*/callback(?:[/?#]|$)') {
        throw "$Label contains a value that cannot be written to a deployment receipt."
    }
}

function Get-AzdReceiptProperty {
    param(
        [Parameter(Mandatory)][object] $Object,
        [Parameter(Mandatory)][string] $Name
    )

    if ($Object -is [System.Collections.IDictionary]) {
        if (-not $Object.Contains($Name)) { throw "Receipt must contain $Name." }
        return $Object[$Name]
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { throw "Receipt must contain $Name." }
    return $property.Value
}

function Assert-AzdReceiptSafeValue {
    param(
        [Parameter(Mandatory)][object] $Value,
        [int] $Depth = 0,
        [ref] $ItemCount
    )

    if ($Depth -gt 16) { throw 'Receipt details are nested too deeply.' }
    $ItemCount.Value = [int] $ItemCount.Value + 1
    if ($ItemCount.Value -gt $script:MaxCollectionItems) { throw 'Receipt details contain too many values.' }
    if ($null -eq $Value -or $Value -is [bool] -or $Value -is [byte] -or $Value -is [int16] -or
        $Value -is [int32] -or $Value -is [int64] -or $Value -is [uint16] -or $Value -is [uint32] -or
        $Value -is [uint64] -or $Value -is [decimal] -or $Value -is [double]) { return }
    if ($Value -is [string]) {
        Assert-AzdReceiptText -Value $Value -Label 'Receipt detail value'
        return
    }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            $key = [string] $key
            Assert-AzdReceiptText -Value $key -Label 'Receipt detail key' -MaximumLength 128
            if ($key -match $script:SensitiveKeyPattern) { throw 'Receipt detail key is sensitive.' }
            Assert-AzdReceiptSafeValue -Value $Value[$key] -Depth ($Depth + 1) -ItemCount $ItemCount
        }
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        foreach ($item in $Value) {
            Assert-AzdReceiptSafeValue -Value $item -Depth ($Depth + 1) -ItemCount $ItemCount
        }
        return
    }
    if ($Value -is [psobject]) {
        $properties = @($Value.PSObject.Properties | Where-Object { $_.MemberType -match 'Property' })
        foreach ($property in $properties) {
            Assert-AzdReceiptText -Value $property.Name -Label 'Receipt detail key' -MaximumLength 128
            if ($property.Name -match $script:SensitiveKeyPattern) { throw 'Receipt detail key is sensitive.' }
            Assert-AzdReceiptSafeValue -Value $property.Value -Depth ($Depth + 1) -ItemCount $ItemCount
        }
        return
    }
    throw 'Receipt details contain an unsupported value type.'
}

function Assert-AzdReceiptArtifactPath {
    param([Parameter(Mandatory)][string] $Path)

    Assert-AzdReceiptText -Value $Path -Label 'Receipt artifact' -MaximumLength 512
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 512 -or
        [System.IO.Path]::IsPathRooted($Path) -or $Path -match '[\\\x00-\x1F]' -or
        ($Path -split '/' | Where-Object { $_ -in '.', '..' })) {
        throw 'Receipt artifacts must be bounded repository-relative forward-slash paths.'
    }
}

function Get-AzdReceiptEvidenceProperty {
    param([Parameter(Mandatory)][object] $Object, [Parameter(Mandatory)][string] $Name)

    if ($Object -is [System.Collections.IDictionary]) {
        if (-not $Object.Contains($Name)) { throw "Evidence binding must contain $Name." }
        return $Object[$Name]
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { throw "Evidence binding must contain $Name." }
    return $property.Value
}

function Assert-AzdReceiptEvidenceShape {
    param([Parameter(Mandatory)][object] $Object, [Parameter(Mandatory)][string[]] $Required, [string[]] $Optional = @())

    $names = if ($Object -is [System.Collections.IDictionary]) { @($Object.Keys | ForEach-Object { [string] $_ }) } else { @($Object.PSObject.Properties.Name) }
    foreach ($name in $Required) { if ($name -notin $names) { throw "Evidence binding must contain $name." } }
    $unknown = @($names | Where-Object { $_ -notin @($Required + $Optional) })
    if ($unknown.Count -gt 0) { throw "Evidence binding contains an unknown property: $($unknown[0])." }
}

function Assert-AzdReceiptEvidenceText {
    param([Parameter(Mandatory)][object] $Value, [Parameter(Mandatory)][string] $Label)

    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 128 -or $Value -match '[\x00-\x1F]') {
        throw "$Label must be a bounded nonempty string without control characters."
    }
}

function New-AzdReceiptManagementEvidence {
    param(
        [Parameter(Mandatory)][ValidateSet('resourceMutation', 'cleanup')][string] $EvidenceClass,
        [Parameter(Mandatory)][System.Collections.IDictionary] $Binding,
        [object[]] $NextActions = @()
    )

    Assert-AzdReceiptEvidenceShape -Object $Binding -Required @('project', 'target', 'source', 'operation')
    $project = Get-AzdReceiptEvidenceProperty $Binding project
    $target = Get-AzdReceiptEvidenceProperty $Binding target
    $source = Get-AzdReceiptEvidenceProperty $Binding source
    $operation = Get-AzdReceiptEvidenceProperty $Binding operation
    Assert-AzdReceiptEvidenceShape $project @('id', 'environment')
    Assert-AzdReceiptEvidenceShape $target @('azureCloud', 'tenantId', 'subscriptionId') @('resourceGroup')
    Assert-AzdReceiptEvidenceShape $source @('templateId', 'revision') @('contractDigest')
    Assert-AzdReceiptEvidenceShape $operation @('id', 'kind')

    foreach ($pair in @(
            @((Get-AzdReceiptEvidenceProperty $project id), 'Project ID'),
            @((Get-AzdReceiptEvidenceProperty $project environment), 'Environment'),
            @((Get-AzdReceiptEvidenceProperty $target azureCloud), 'Azure cloud'),
            @((Get-AzdReceiptEvidenceProperty $source templateId), 'Template ID')
        )) { Assert-AzdReceiptEvidenceText -Value $pair[0] -Label $pair[1] }
    if (($target -is [System.Collections.IDictionary] -and $target.Contains('resourceGroup')) -or $target.PSObject.Properties['resourceGroup']) {
        Assert-AzdReceiptEvidenceText -Value (Get-AzdReceiptEvidenceProperty $target resourceGroup) -Label 'Resource group'
    }
    foreach ($name in 'tenantId', 'subscriptionId') {
        $value = [string] (Get-AzdReceiptEvidenceProperty $target $name)
        if ($value -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { throw "$name must be a UUID." }
    }
    $revision = [string] (Get-AzdReceiptEvidenceProperty $source revision)
    if ($revision -ne 'local' -and $revision -notmatch '^[0-9a-f]{40}$') { throw 'Source revision must be a lowercase Git SHA or local.' }
    if (($source -is [System.Collections.IDictionary] -and $source.Contains('contractDigest')) -or $source.PSObject.Properties['contractDigest']) {
        if ([string] (Get-AzdReceiptEvidenceProperty $source contractDigest) -notmatch '^[0-9a-f]{64}$') { throw 'Contract digest must be lowercase SHA-256.' }
    }
    $operationId = [string] (Get-AzdReceiptEvidenceProperty $operation id)
    if ($operationId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { throw 'Operation ID must be a UUID.' }
    $operationKind = [string] (Get-AzdReceiptEvidenceProperty $operation kind)
    $allowedKinds = if ($EvidenceClass -eq 'cleanup') { @('down', 'cleanup') } else { @('provision', 'deploy', 'up') }
    if ($operationKind -notin $allowedKinds) { throw 'Operation kind does not match the receipt evidence class.' }

    if ($NextActions.Count -gt 20) { throw 'Management next actions are limited to 20 items.' }
    $normalizedActions = @($NextActions | ForEach-Object {
            Assert-AzdReceiptEvidenceShape $_ @('code', 'owner', 'priority')
            $code = [string] (Get-AzdReceiptEvidenceProperty $_ code)
            $owner = [string] (Get-AzdReceiptEvidenceProperty $_ owner)
            $priority = [string] (Get-AzdReceiptEvidenceProperty $_ priority)
            if ($code -notin @('reviewWarnings', 'retryOperation', 'verifyResources', 'verifyPermissions', 'proveDelivery', 'completeCleanup')) { throw 'Management next-action code is not registered.' }
            if ($owner -notin @('operator', 'subscriptionOwner', 'identityAdmin', 'messagingAdmin', 'applicationOwner', 'templateMaintainer')) { throw 'Management next-action owner is not registered.' }
            if ($priority -notin @('required', 'recommended')) { throw 'Management next-action priority is invalid.' }
            [ordered]@{ code = $code; owner = $owner; priority = $priority }
        })
    $normalizedBinding = $Binding | ConvertTo-Json -Depth 10 -Compress | ConvertFrom-Json -AsHashtable
    [ordered]@{ version = '1'; evidenceClass = $EvidenceClass; binding = $normalizedBinding; nextActions = $normalizedActions }
}

function Assert-AzdReceiptShape {
    param([Parameter(Mandatory)][object] $Receipt)

    $schemaVersion = Get-AzdReceiptProperty -Object $Receipt -Name 'schemaVersion'
    if ($schemaVersion -isnot [string] -or $schemaVersion -notin @('1.0', '1.1')) { throw 'Receipt schemaVersion is unsupported.' }
    $template = Get-AzdReceiptProperty -Object $Receipt -Name 'template'
    if ($template -isnot [string]) { throw 'Template must be a string.' }
    Assert-AzdReceiptText -Value $template -Label 'Template' -MaximumLength 128
    $templateVersion = Get-AzdReceiptProperty -Object $Receipt -Name 'templateVersion'
    if ($templateVersion -isnot [string]) { throw 'Template version must be a string.' }
    Assert-AzdReceiptText -Value $templateVersion -Label 'Template version' -MaximumLength 128
    $mode = Get-AzdReceiptProperty -Object $Receipt -Name 'mode'
    if ($mode -isnot [string]) { throw 'Receipt mode must be a string.' }
    if ($mode -notin @('plan', 'enforce')) { throw 'Receipt mode must be plan or enforce.' }
    $summary = Get-AzdReceiptProperty -Object $Receipt -Name 'summary'
    $applied = Get-AzdReceiptProperty -Object $summary -Name 'applied'
    if ($mode -eq 'plan' -and [int64] $applied -ne 0) {
        throw 'Plan receipts cannot report applied actions.'
    }
    $details = Get-AzdReceiptProperty -Object $Receipt -Name 'details'
    $hasEvidence = if ($details -is [System.Collections.IDictionary]) { $details.Contains('azdManagementEvidence') } else { $null -ne $details.PSObject.Properties['azdManagementEvidence'] }
    if (($schemaVersion -eq '1.1') -ne $hasEvidence) { throw 'Receipt schemaVersion 1.1 requires management evidence and 1.0 forbids it.' }
    $itemCount = 0
    Assert-AzdReceiptSafeValue -Value $details -ItemCount ([ref] $itemCount)
    $artifacts = @(Get-AzdReceiptProperty -Object $Receipt -Name 'artifacts')
    $actions = @(Get-AzdReceiptProperty -Object $Receipt -Name 'operationalActions')
    if ($artifacts.Count -gt $script:MaxCollectionItems -or $actions.Count -gt $script:MaxCollectionItems) {
        throw 'Receipt artifacts and operational actions are limited to 500 items each.'
    }
    foreach ($artifact in $artifacts) {
        if ($artifact -isnot [string]) { throw 'Receipt artifacts must be strings.' }
        Assert-AzdReceiptArtifactPath -Path $artifact
    }
    foreach ($action in $actions) {
        if ($action -isnot [string]) { throw 'Operational actions must be strings.' }
        Assert-AzdReceiptText -Value $action -Label 'Operational action'
    }
}

function Assert-AzdReceiptOutputPath {
    param([Parameter(Mandatory)][string] $OutputPath)

    if ([string]::IsNullOrWhiteSpace($OutputPath) -or $OutputPath.Length -gt 512 -or
        [System.IO.Path]::IsPathRooted($OutputPath) -or $OutputPath -match '[\\:\x00-\x1F]' -or
        $OutputPath -match '[\\/]$') {
        throw 'OutputPath must be a bounded repository-relative file path.'
    }
    $segments = @($OutputPath -split '/')
    if ($segments.Count -eq 0 -or ($segments | Where-Object { [string]::IsNullOrEmpty($_) -or $_ -in '.', '..' })) {
        throw 'OutputPath cannot contain empty, dot, or parent-traversal segments.'
    }
    return $segments
}

function Assert-AzdReceiptSafePath {
    param(
        [Parameter(Mandatory)][string] $RepositoryRoot,
        [Parameter(Mandatory)][string[]] $Segments,
        [Parameter(Mandatory)][string] $Message
    )

    $cursor = $RepositoryRoot
    foreach ($segment in $Segments) {
        $cursor = Join-Path $cursor $segment
        if ((Test-Path -LiteralPath $cursor) -and (Test-AzdReceiptReparsePoint -Path $cursor)) {
            throw $Message
        }
    }
}

function New-AzdDeploymentReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Template,
        [Parameter(Mandatory)][string] $TemplateVersion,
        [Parameter(Mandatory)][ValidateSet('plan', 'enforce')][string] $Mode,
        [datetimeoffset] $GeneratedAt = [datetimeoffset]::UtcNow,
        [ValidateRange(0, [int]::MaxValue)][int] $Applied = 0,
        [ValidateRange(0, [int]::MaxValue)][int] $Unchanged = 0,
        [ValidateRange(0, [int]::MaxValue)][int] $Skipped = 0,
        [ValidateRange(0, [int]::MaxValue)][int] $Warnings = 0,
        [ValidateRange(0, [int]::MaxValue)][int] $Failed = 0,
        [string[]] $Artifacts = @(),
        [string[]] $OperationalActions = @(),
        [hashtable] $Details = @{},
        [ValidateSet('resourceMutation', 'cleanup')][string] $EvidenceClass,
        [System.Collections.IDictionary] $EvidenceBinding,
        [object[]] $ManagementNextActions = @()
    )

    Assert-AzdReceiptText -Value $Template -Label 'Template' -MaximumLength 128
    Assert-AzdReceiptText -Value $TemplateVersion -Label 'Template version' -MaximumLength 128
    if ($Mode -eq 'plan' -and $Applied -ne 0) { throw 'Plan receipts cannot report applied actions.' }
    $normalizedMode = $Mode.ToLowerInvariant()
    if ($Artifacts.Count -gt $script:MaxCollectionItems -or $OperationalActions.Count -gt $script:MaxCollectionItems) {
        throw 'Receipt artifacts and operational actions are limited to 500 items each.'
    }
    $evidenceRequested = $PSBoundParameters.ContainsKey('EvidenceClass') -or $PSBoundParameters.ContainsKey('EvidenceBinding') -or $PSBoundParameters.ContainsKey('ManagementNextActions')
    if ($evidenceRequested -and (-not $PSBoundParameters.ContainsKey('EvidenceClass') -or -not $PSBoundParameters.ContainsKey('EvidenceBinding'))) {
        throw 'EvidenceClass and EvidenceBinding are both required for bound receipts.'
    }
    $normalizedDetails = [ordered]@{}
    foreach ($key in $Details.Keys) { $normalizedDetails[[string] $key] = $Details[$key] }
    if ($normalizedDetails.Contains('azdManagementEvidence')) { throw 'Details cannot define reserved azdManagementEvidence.' }
    if ($evidenceRequested) {
        $normalizedDetails.azdManagementEvidence = New-AzdReceiptManagementEvidence -EvidenceClass $EvidenceClass -Binding $EvidenceBinding -NextActions $ManagementNextActions
    }
    $receipt = [pscustomobject] [ordered]@{
        schemaVersion = if ($evidenceRequested) { '1.1' } else { '1.0' }
        generatedAt = $GeneratedAt.UtcDateTime.ToString('o')
        template = $Template
        templateVersion = $TemplateVersion
        mode = $normalizedMode
        summary = [ordered]@{
            applied = $Applied
            unchanged = $Unchanged
            skipped = $Skipped
            warnings = $Warnings
            failed = $Failed
        }
        artifacts = @($Artifacts)
        operationalActions = @($OperationalActions)
        details = $normalizedDetails
    }
    Assert-AzdReceiptShape -Receipt $receipt
    return $receipt
}

function Write-AzdDeploymentReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object] $Receipt,
        [Parameter(Mandatory)][string] $RepositoryRoot,
        [AllowEmptyString()][string] $OutputPath = $script:DefaultOutputPath,
        [string] $SchemaPath = (Join-Path $PSScriptRoot 'deployment-receipt.schema.json')
    )

    $segments = Assert-AzdReceiptOutputPath -OutputPath $OutputPath
    $root = [System.IO.Path]::GetFullPath($RepositoryRoot)
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'RepositoryRoot must be an existing directory.' }
    if (Test-AzdReceiptReparsePoint -Path $root) { throw 'RepositoryRoot cannot be a symbolic link or reparse point.' }
    $target = [System.IO.Path]::GetFullPath((Join-Path $root $OutputPath))
    $rootPrefix = $root.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    $comparison = if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
    if (-not $target.StartsWith($rootPrefix, $comparison)) { throw 'OutputPath resolves outside RepositoryRoot.' }

    Assert-AzdReceiptSafePath -RepositoryRoot $root -Segments $segments -Message 'OutputPath cannot traverse a symbolic link or reparse point.'
    Assert-AzdReceiptShape -Receipt $Receipt
    if (-not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) { throw 'The deployment receipt schema is unavailable.' }
    $json = $Receipt | ConvertTo-Json -Depth 30
    $payload = $json + "`n"
    if ([System.Text.Encoding]::UTF8.GetByteCount($payload) -gt $script:MaxReceiptBytes) { throw 'Deployment receipt exceeds 1 MiB.' }
    try {
        if (-not ($json | Test-Json -SchemaFile $SchemaPath -ErrorAction Stop)) { throw 'Schema validation returned false.' }
    }
    catch { throw 'The deployment receipt does not satisfy its schema.' }

    $directory = Split-Path -Parent $target
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    if (Test-AzdReceiptReparsePoint -Path $directory) { throw 'Output directory cannot be a symbolic link or reparse point.' }
    if (Test-Path -LiteralPath $target -PathType Container) { throw 'OutputPath must name a file, not an existing directory.' }
    $temporaryPath = Join-Path $directory ('.{0}.{1}.tmp' -f [System.IO.Path]::GetFileName($target), [guid]::NewGuid().ToString('N'))
    try {
        [System.IO.File]::WriteAllText($temporaryPath, $payload, [System.Text.UTF8Encoding]::new($false))
        if (Test-AzdReceiptReparsePoint -Path $directory) {
            throw 'Output directory became a symbolic link or reparse point before the receipt could be committed.'
        }
        Assert-AzdReceiptSafePath -RepositoryRoot $root -Segments $segments -Message 'OutputPath became a symbolic link or reparse point before the receipt could be committed.'
        if (Test-Path -LiteralPath $target -PathType Container) {
            throw 'OutputPath became an existing directory before the receipt could be committed.'
        }
        [System.IO.File]::Move($temporaryPath, $target, $true)
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
    }
    return [System.IO.Path]::GetRelativePath($root, $target).Replace([System.IO.Path]::DirectorySeparatorChar, '/')
}

Export-ModuleMember -Function 'New-AzdDeploymentReceipt', 'Write-AzdDeploymentReceipt'
