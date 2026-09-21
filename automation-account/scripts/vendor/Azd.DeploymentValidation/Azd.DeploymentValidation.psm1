Set-StrictMode -Version Latest

$script:StatusOrder = @('pass', 'fail', 'warning', 'info', 'skipped', 'planned')
$script:PhaseOrder = @('context', 'infrastructure', 'identity', 'configuration', 'security', 'runtime', 'delivery')
$script:SensitiveNamePattern = '(?i)(^|[-_])(authorization(?:.?header)?|(?:access|refresh|id|bearer)?.?token|secret|password|credential|cookie|assertion|certificate|client.?secret|(?:private|api|host|function|account)?.?key|connection.?string|shared.?access.?signature|callback(?:.?(?:url|uri))?|trigger.?url|webhook.?(?:url|uri)|sas|signature|sig)([-_]|$)'
$script:SensitiveUrlPattern = '(?i)[?&](sig|signature|token|code|key|secret|sas)='
$script:SensitiveTextPattern = '(?i)(AccountKey|SharedAccessSignature|ClientSecret|Password|ConnectionString)='

function ConvertTo-AzdSafeData {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [object] $Value,

        [string] $Name = ''
    )

    process {
        if ($Name -match $script:SensitiveNamePattern) {
            return '[REDACTED]'
        }
        if ($null -eq $Value) {
            return $null
        }
        if ($Value -is [string]) {
            if ($Value -match $script:SensitiveUrlPattern) {
                return '[REDACTED URL]'
            }
            if ($Value -match $script:SensitiveTextPattern) {
                return '[REDACTED]'
            }
            $safeString = [regex]::Replace($Value, '(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+', '[REDACTED BEARER TOKEN]')
            $safeString = [regex]::Replace($safeString, '\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b', '[REDACTED JWT]')
            return $safeString
        }
        if ($Value -is [System.Collections.IDictionary]) {
            $safe = [ordered]@{}
            foreach ($key in $Value.Keys) {
                $child = $Value[$key]
                if ($child -is [System.Collections.IEnumerable] -and $child -isnot [string] -and $child -isnot [System.Collections.IDictionary]) {
                    [object[]] $safeItems = @($child | ForEach-Object { ConvertTo-AzdSafeData -Value $_ -Name ([string] $key) })
                    $safe[[string] $key] = $safeItems
                }
                else {
                    $safe[[string] $key] = ConvertTo-AzdSafeData -Value $child -Name ([string] $key)
                }
            }
            return $safe
        }
        if ($Value -is [System.Management.Automation.PSCustomObject]) {
            $safe = [ordered]@{}
            foreach ($property in $Value.PSObject.Properties) {
                $child = $property.Value
                if ($child -is [System.Collections.IEnumerable] -and $child -isnot [string] -and $child -isnot [System.Collections.IDictionary]) {
                    [object[]] $safeItems = @($child | ForEach-Object { ConvertTo-AzdSafeData -Value $_ -Name $property.Name })
                    $safe[$property.Name] = $safeItems
                }
                else {
                    $safe[$property.Name] = ConvertTo-AzdSafeData -Value $child -Name $property.Name
                }
            }
            return $safe
        }
        if ($Value -is [System.Collections.IEnumerable]) {
            return @($Value | ForEach-Object { ConvertTo-AzdSafeData -Value $_ })
        }
        if ($Value -is [ValueType]) {
            return $Value
        }
        return ConvertTo-AzdSafeData -Value ([string] $Value) -Name $Name
    }
}

function New-AzdCheckOutcome {
    [CmdletBinding()]
    param(
        [ValidateSet('pass', 'fail', 'warning', 'info', 'skipped')]
        [string] $Status = 'pass',

        [Parameter(Mandatory)]
        [string] $Summary,

        [AllowNull()]
        [object] $Expected,

        [AllowNull()]
        [object] $Actual,

        [hashtable] $Evidence = @{},

        [hashtable] $Metadata = @{},

        [AllowNull()]
        [string] $Remediation
    )

    $outcome = [pscustomobject] [ordered]@{
        status = $Status
        summary = $Summary
        expected = $Expected
        actual = $Actual
        evidence = $Evidence
        metadata = $Metadata
        remediation = $Remediation
    }
    $outcome.PSObject.TypeNames.Insert(0, 'Azd.Validation.CheckOutcome')
    return $outcome
}

function New-AzdCheckFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-z][A-Za-z0-9.]+$')]
        [string] $Code,

        [Parameter(Mandatory)]
        [string] $Summary,

        [AllowNull()]
        [object] $Expected,

        [hashtable] $Details = @{},

        [Parameter(Mandatory)]
        [string] $Remediation
    )

    if (@($Details.Keys | Where-Object { [string]::Equals(
                    [string] $_, 'failureCode', [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) {
        throw "Details cannot redefine the reserved 'failureCode' field."
    }

    $actual = [ordered] @{ failureCode = $Code }
    foreach ($name in $Details.Keys) {
        $actual[[string] $name] = $Details[$name]
    }
    New-AzdCheckOutcome -Status fail -Summary $Summary -Expected $Expected `
        -Actual $actual -Remediation $Remediation
}

function New-AzdValidationCheckDefinition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-z][a-z0-9.-]+$')]
        [string] $Id,

        [Parameter(Mandatory)]
        [ValidateSet('context', 'infrastructure', 'identity', 'configuration', 'security', 'runtime', 'delivery')]
        [string] $Phase,

        [Parameter(Mandatory)]
        [string] $Title,

        [Parameter(Mandatory)]
        [string] $Summary,

        [Parameter(Mandatory)]
        [scriptblock] $Action,

        [ValidateSet('none', 'readOnly', 'negativeProbe', 'syntheticDelivery')]
        [string] $SideEffect = 'readOnly',

        [AllowNull()]
        [object] $Expected,

        [AllowNull()]
        [string] $Remediation,

        [ValidatePattern('^[a-z][a-z0-9.-]+$')]
        [string[]] $DependsOn = @(),

        [string] $SkipReason
    )

    $definition = [pscustomobject] [ordered]@{
        id = $Id
        phase = $Phase
        title = $Title
        summary = $Summary
        action = $Action
        sideEffect = $SideEffect
        expected = $Expected
        remediation = $Remediation
        dependsOn = @($DependsOn)
        skipReason = $SkipReason
    }
    $definition.PSObject.TypeNames.Insert(0, 'Azd.Validation.CheckDefinition')
    return $definition
}

function Invoke-AzdValidationSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Definitions,

        [switch] $Plan,

        [switch] $AllowSyntheticDelivery
    )

    $declaredIds = @{}
    foreach ($definition in $Definitions) {
        if ($definition.PSObject.TypeNames -notcontains 'Azd.Validation.CheckDefinition') {
            throw 'Project adapters must return definitions created by New-AzdValidationCheckDefinition.'
        }
        if ($declaredIds.ContainsKey($definition.id)) {
            throw "Project validation check ID '$($definition.id)' is duplicated."
        }
        foreach ($dependencyId in @($definition.dependsOn)) {
            if (-not $declaredIds.ContainsKey($dependencyId)) {
                throw "Project validation check '$($definition.id)' depends on unknown or non-earlier check '$dependencyId'."
            }
        }
        $declaredIds[$definition.id] = $true
    }

    $completedStatuses = @{}
    foreach ($definition in $Definitions) {
        $effectiveSkipReason = $definition.skipReason
        if (-not $Plan -and -not $effectiveSkipReason) {
            $blockedDependencies = @(
                foreach ($dependencyId in @($definition.dependsOn)) {
                    if (-not $completedStatuses.ContainsKey($dependencyId) -or
                        $completedStatuses[$dependencyId] -notin 'pass', 'warning', 'info') {
                        $dependencyId
                    }
                }
            )
            if ($blockedDependencies.Count -gt 0) {
                $effectiveSkipReason = 'Prerequisite checks did not pass: {0}.' -f ($blockedDependencies -join ', ')
            }
        }
        $result = Invoke-AzdValidationCheck `
            -Id $definition.id `
            -Phase $definition.phase `
            -Title $definition.title `
            -Summary $definition.summary `
            -Action $definition.action `
            -SideEffect $definition.sideEffect `
            -Expected $definition.expected `
            -Remediation $definition.remediation `
            -SkipReason $effectiveSkipReason `
            -Plan:$Plan `
            -AllowSyntheticDelivery:$AllowSyntheticDelivery
        $completedStatuses[$definition.id] = $result.status
        $result
    }
}

function Invoke-AzdValidationCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-z][a-z0-9.-]+$')]
        [string] $Id,

        [Parameter(Mandatory)]
        [ValidateSet('context', 'infrastructure', 'identity', 'configuration', 'security', 'runtime', 'delivery')]
        [string] $Phase,

        [Parameter(Mandatory)]
        [string] $Title,

        [Parameter(Mandatory)]
        [string] $Summary,

        [Parameter(Mandatory)]
        [scriptblock] $Action,

        [ValidateSet('none', 'readOnly', 'negativeProbe', 'syntheticDelivery')]
        [string] $SideEffect = 'readOnly',

        [AllowNull()]
        [object] $Expected,

        [AllowNull()]
        [string] $Remediation,

        [switch] $Plan,

        [switch] $AllowSyntheticDelivery,

        [string] $SkipReason
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'pass'
    $actual = $null
    $evidence = @{}
    $metadata = @{}
    $resultSummary = $Summary
    $resultRemediation = $Remediation

    if ($Plan) {
        $status = if ($SkipReason) { 'skipped' } else { 'planned' }
        if ($SkipReason) { $resultSummary = $SkipReason }
    }
    elseif ($SkipReason) {
        $status = 'skipped'
        $resultSummary = $SkipReason
    }
    elseif ($SideEffect -eq 'syntheticDelivery' -and -not $AllowSyntheticDelivery) {
        $status = 'skipped'
        $resultSummary = 'Synthetic delivery was not authorized. Rerun with -TestDelivery to execute this check.'
    }
    else {
        try {
            $actionOutput = @(& $Action)
            if ($actionOutput.Count -gt 1) {
                throw 'A validation action returned more than one value. Return one New-AzdCheckOutcome object or no output.'
            }
            if ($actionOutput.Count -eq 1) {
                $outcome = $actionOutput[0]
                if ($outcome.PSObject.TypeNames -notcontains 'Azd.Validation.CheckOutcome') {
                    throw 'A validation action returned an unsupported value. Use New-AzdCheckOutcome for structured output.'
                }
                $status = $outcome.status
                $resultSummary = $outcome.summary
                $Expected = $outcome.expected
                $actual = $outcome.actual
                $evidence = $outcome.evidence
                $metadata = $outcome.metadata
                if ($outcome.remediation) { $resultRemediation = $outcome.remediation }
            }
        }
        catch {
            $status = 'fail'
            $resultSummary = $Summary
            $actual = [ordered]@{ exceptionType = $_.Exception.GetType().FullName }
        }
    }

    $stopwatch.Stop()
    return [pscustomobject] [ordered]@{
        id = $Id
        phase = $Phase
        title = $Title
        status = $status
        summary = $resultSummary
        sideEffect = $SideEffect
        durationMs = [int] $stopwatch.ElapsedMilliseconds
        expected = ConvertTo-AzdSafeData -Value $Expected
        actual = ConvertTo-AzdSafeData -Value $actual
        evidence = ConvertTo-AzdSafeData -Value $evidence
        remediation = $resultRemediation
        metadata = ConvertTo-AzdSafeData -Value $metadata
    }
}

function Get-AzdValidationEvidenceProperty {
    param([Parameter(Mandatory)][object] $Object, [Parameter(Mandatory)][string] $Name)
    if ($Object -is [System.Collections.IDictionary]) {
        if (-not $Object.Contains($Name)) { throw "Evidence binding must contain $Name." }
        return $Object[$Name]
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { throw "Evidence binding must contain $Name." }
    return $property.Value
}

function Assert-AzdValidationEvidenceShape {
    param([Parameter(Mandatory)][object] $Object, [Parameter(Mandatory)][string[]] $Required, [string[]] $Optional = @())
    $names = if ($Object -is [System.Collections.IDictionary]) { @($Object.Keys | ForEach-Object { [string] $_ }) } else { @($Object.PSObject.Properties.Name) }
    foreach ($name in $Required) { if ($name -notin $names) { throw "Evidence binding must contain $name." } }
    $unknown = @($names | Where-Object { $_ -notin @($Required + $Optional) })
    if ($unknown.Count -gt 0) { throw "Evidence binding contains an unknown property: $($unknown[0])." }
}

function Assert-AzdValidationEvidenceText {
    param([Parameter(Mandatory)][object] $Value, [Parameter(Mandatory)][string] $Label)
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 128 -or $Value -match '[\x00-\x1F]') {
        throw "$Label must be a bounded nonempty string without control characters."
    }
}

function New-AzdValidationManagementEvidence {
    param(
        [Parameter(Mandatory)][ValidateSet('validation', 'delivery')][string] $EvidenceClass,
        [Parameter(Mandatory)][System.Collections.IDictionary] $Binding,
        [object[]] $NextActions = @()
    )
    Assert-AzdValidationEvidenceShape $Binding @('project', 'target', 'source', 'operation')
    $project = Get-AzdValidationEvidenceProperty $Binding project
    $target = Get-AzdValidationEvidenceProperty $Binding target
    $source = Get-AzdValidationEvidenceProperty $Binding source
    $operation = Get-AzdValidationEvidenceProperty $Binding operation
    Assert-AzdValidationEvidenceShape $project @('id', 'environment')
    Assert-AzdValidationEvidenceShape $target @('azureCloud', 'tenantId', 'subscriptionId') @('resourceGroup')
    Assert-AzdValidationEvidenceShape $source @('templateId', 'revision') @('contractDigest')
    Assert-AzdValidationEvidenceShape $operation @('id', 'kind')
    foreach ($pair in @(
            @((Get-AzdValidationEvidenceProperty $project id), 'Project ID'),
            @((Get-AzdValidationEvidenceProperty $project environment), 'Environment'),
            @((Get-AzdValidationEvidenceProperty $target azureCloud), 'Azure cloud'),
            @((Get-AzdValidationEvidenceProperty $source templateId), 'Template ID')
        )) { Assert-AzdValidationEvidenceText $pair[0] $pair[1] }
    if (($target -is [System.Collections.IDictionary] -and $target.Contains('resourceGroup')) -or $target.PSObject.Properties['resourceGroup']) {
        Assert-AzdValidationEvidenceText (Get-AzdValidationEvidenceProperty $target resourceGroup) 'Resource group'
    }
    foreach ($name in 'tenantId', 'subscriptionId') {
        if ([string] (Get-AzdValidationEvidenceProperty $target $name) -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { throw "$name must be a UUID." }
    }
    $revision = [string] (Get-AzdValidationEvidenceProperty $source revision)
    if ($revision -ne 'local' -and $revision -notmatch '^[0-9a-f]{40}$') { throw 'Source revision must be a lowercase Git SHA or local.' }
    if (($source -is [System.Collections.IDictionary] -and $source.Contains('contractDigest')) -or $source.PSObject.Properties['contractDigest']) {
        if ([string] (Get-AzdValidationEvidenceProperty $source contractDigest) -notmatch '^[0-9a-f]{64}$') { throw 'Contract digest must be lowercase SHA-256.' }
    }
    if ([string] (Get-AzdValidationEvidenceProperty $operation id) -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { throw 'Operation ID must be a UUID.' }
    $kind = [string] (Get-AzdValidationEvidenceProperty $operation kind)
    if (($EvidenceClass -eq 'delivery' -and $kind -ne 'delivery') -or ($EvidenceClass -eq 'validation' -and $kind -ne 'validate')) { throw 'Operation kind does not match the validation evidence class.' }
    if ($NextActions.Count -gt 20) { throw 'Management next actions are limited to 20 items.' }
    $normalizedActions = @($NextActions | ForEach-Object {
            Assert-AzdValidationEvidenceShape $_ @('code', 'owner', 'priority')
            $code = [string] (Get-AzdValidationEvidenceProperty $_ code)
            $owner = [string] (Get-AzdValidationEvidenceProperty $_ owner)
            $priority = [string] (Get-AzdValidationEvidenceProperty $_ priority)
            if ($code -notin @('reviewWarnings', 'retryOperation', 'verifyResources', 'verifyPermissions', 'proveDelivery', 'completeCleanup')) { throw 'Management next-action code is not registered.' }
            if ($owner -notin @('operator', 'subscriptionOwner', 'identityAdmin', 'messagingAdmin', 'applicationOwner', 'templateMaintainer')) { throw 'Management next-action owner is not registered.' }
            if ($priority -notin @('required', 'recommended')) { throw 'Management next-action priority is invalid.' }
            [ordered]@{ code = $code; owner = $owner; priority = $priority }
        })
    $normalizedBinding = $Binding | ConvertTo-Json -Depth 10 -Compress | ConvertFrom-Json -AsHashtable
    [ordered]@{ version = '1'; evidenceClass = $EvidenceClass; binding = $normalizedBinding; nextActions = $normalizedActions }
}

function New-AzdValidationReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $TemplateName,

        [Parameter(Mandatory)]
        [string] $TemplateVersion,

        [Parameter(Mandatory)]
        [ValidateSet('plan', 'verify', 'delivery')]
        [string] $Mode,

        [Parameter(Mandatory)]
        [datetimeoffset] $StartedAt,

        [Parameter(Mandatory)]
        [object[]] $Checks,

        [hashtable] $Environment = @{},

        [hashtable] $Requirements = @{ tools = @(); modules = @(); permissions = @() },

        [string[]] $NextSteps = @(),

        [ValidateSet('validation', 'delivery')][string] $EvidenceClass,

        [System.Collections.IDictionary] $EvidenceBinding,

        [object[]] $ManagementNextActions = @()
    )

    $normalizedChecks = [System.Collections.Generic.List[object]]::new()
    $seenIds = @{}
    for ($checkIndex = 0; $checkIndex -lt $Checks.Count; $checkIndex++) {
        $check = $Checks[$checkIndex]
        try {
            foreach ($requiredProperty in 'id', 'phase', 'title', 'status', 'summary', 'sideEffect', 'durationMs', 'evidence') {
                if ($check.PSObject.Properties.Name -notcontains $requiredProperty) {
                    throw "Validation check is missing '$requiredProperty'."
                }
            }
            if ([string] $check.id -notmatch '^[a-z][a-z0-9.-]+$') { throw 'Validation check ID is invalid.' }
            if ([string] $check.phase -notin $script:PhaseOrder) { throw 'Validation check phase is invalid.' }
            if ([string] $check.status -notin $script:StatusOrder) { throw 'Validation check status is invalid.' }
            if ([string] $check.sideEffect -notin 'none', 'readOnly', 'negativeProbe', 'syntheticDelivery') { throw 'Validation check side effect is invalid.' }
            if ([int64] $check.durationMs -lt 0) { throw 'Validation check duration is invalid.' }
            if ($seenIds.ContainsKey([string] $check.id)) { throw 'Validation check ID is duplicated.' }
            if ($Mode -eq 'plan' -and [string] $check.status -notin 'planned', 'skipped', 'fail') {
                throw 'Plan reports can contain only planned, skipped, or failed checks.'
            }
            if ($Mode -eq 'verify' -and [string] $check.sideEffect -eq 'syntheticDelivery' -and [string] $check.status -notin 'skipped', 'planned') {
                throw 'Verify mode cannot contain an executed synthetic-delivery check.'
            }
            $seenIds[[string] $check.id] = $true
            $normalizedChecks.Add([pscustomobject] (ConvertTo-AzdSafeData -Value $check))
        }
        catch {
            $normalizedChecks.Add([pscustomobject] [ordered]@{
                id = "runtime.validation-harness.$checkIndex"
                phase = 'runtime'
                title = 'Validation adapter contract'
                status = 'fail'
                summary = 'A project adapter returned an invalid validation check.'
                sideEffect = 'none'
                durationMs = 0
                expected = 'A complete, unique check result that follows the validation contract.'
                actual = [ordered]@{ exceptionType = $_.Exception.GetType().FullName }
                evidence = [ordered]@{ checkIndex = $checkIndex }
                remediation = 'Correct the project validation adapter and rerun Test-Deployment.ps1.'
                metadata = [ordered]@{}
            })
        }
    }

    $completedAt = [datetimeoffset]::UtcNow
    $summary = [ordered]@{}
    foreach ($status in $script:StatusOrder) {
        $summary[$status] = @($normalizedChecks | Where-Object status -eq $status).Count
    }

    $outcome = if ($summary.fail -gt 0) {
        'failed'
    }
    elseif ($Mode -eq 'plan') {
        'planned'
    }
    elseif ($summary.warning -gt 0) {
        'passedWithWarnings'
    }
    else {
        'passed'
    }

    $orderedChecks = @($normalizedChecks | Sort-Object `
        @{ Expression = { $script:PhaseOrder.IndexOf($_.phase) } },
        @{ Expression = { $_.id } })

    $evidenceRequested = $PSBoundParameters.ContainsKey('EvidenceClass') -or $PSBoundParameters.ContainsKey('EvidenceBinding') -or $PSBoundParameters.ContainsKey('ManagementNextActions')
    if ($evidenceRequested -and (-not $PSBoundParameters.ContainsKey('EvidenceClass') -or -not $PSBoundParameters.ContainsKey('EvidenceBinding'))) {
        throw 'EvidenceClass and EvidenceBinding are both required for bound validation reports.'
    }
    if ($evidenceRequested -and (($Mode -eq 'delivery') -ne ($EvidenceClass -eq 'delivery'))) {
        throw 'Validation mode and evidence class must agree.'
    }
    $normalizedEnvironment = [ordered]@{}
    foreach ($key in $Environment.Keys) { $normalizedEnvironment[[string] $key] = $Environment[$key] }
    if ($evidenceRequested) {
        $metadata = [ordered]@{}
        if ($normalizedEnvironment.Contains('metadata')) {
            if ($normalizedEnvironment.metadata -isnot [System.Collections.IDictionary]) { throw 'Environment metadata must be an object for bound evidence.' }
            foreach ($key in $normalizedEnvironment.metadata.Keys) { $metadata[[string] $key] = $normalizedEnvironment.metadata[$key] }
        }
        if ($metadata.Contains('azdManagementEvidence')) { throw 'Environment metadata cannot define reserved azdManagementEvidence.' }
        $metadata.azdManagementEvidence = New-AzdValidationManagementEvidence -EvidenceClass $EvidenceClass -Binding $EvidenceBinding -NextActions $ManagementNextActions
        $normalizedEnvironment.metadata = $metadata
    }

    return [pscustomobject] [ordered]@{
        schemaVersion = if ($evidenceRequested) { '1.1' } else { '1.0' }
        reportType = 'azdDeploymentValidation'
        startedAt = $StartedAt.UtcDateTime.ToString('o')
        completedAt = $completedAt.UtcDateTime.ToString('o')
        durationMs = [int] [math]::Max(0, ($completedAt - $StartedAt).TotalMilliseconds)
        template = [ordered]@{ name = $TemplateName; version = $TemplateVersion }
        environment = ConvertTo-AzdSafeData -Value $normalizedEnvironment
        mode = $Mode
        requirements = ConvertTo-AzdSafeData -Value $Requirements
        outcome = $outcome
        summary = $summary
        checks = $orderedChecks
        nextSteps = @(ConvertTo-AzdSafeData -Value $NextSteps)
    }
}

function Write-AzdValidationReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Report,

        [Parameter(Mandatory)]
        [string] $OutputPath,

        [Parameter(Mandatory)]
        [string] $RepositoryRoot,

        [string] $SchemaPath = (Join-Path $PSScriptRoot 'deployment-validation.schema.json')
    )

    if ([System.IO.Path]::IsPathRooted($OutputPath) -or $OutputPath -split '[\\/]' -contains '..') {
        throw 'OutputPath must be repository-relative and cannot contain parent traversal.'
    }

    $root = [System.IO.Path]::GetFullPath($RepositoryRoot)
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw 'RepositoryRoot must be an existing directory.'
    }
    if ((Get-Item -LiteralPath $root).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw 'RepositoryRoot cannot be a symbolic link or reparse point.'
    }
    $target = [System.IO.Path]::GetFullPath((Join-Path $root $OutputPath))
    $rootPrefix = $root.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    $isWindowsPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows)
    $comparison = if ($isWindowsPlatform) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
    if (-not $target.StartsWith($rootPrefix, $comparison)) {
        throw 'OutputPath resolves outside RepositoryRoot.'
    }

    $cursor = $root
    foreach ($segment in $OutputPath -split '[\\/]') {
        $cursor = Join-Path $cursor $segment
        if ((Test-Path -LiteralPath $cursor) -and
            ((Get-Item -LiteralPath $cursor).Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw 'OutputPath cannot traverse a symbolic link or reparse point.'
        }
    }

    $directory = Split-Path -Parent $target
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $temporaryPath = Join-Path $directory ('.{0}.{1}.tmp' -f [System.IO.Path]::GetFileName($target), [guid]::NewGuid().ToString('N'))
    try {
        $safeReport = [pscustomobject] (ConvertTo-AzdSafeData -Value $Report)
        $json = $safeReport | ConvertTo-Json -Depth 30
        if (-not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) {
            throw 'The deployment-validation schema is unavailable.'
        }
        try {
            if (-not ($json | Test-Json -SchemaFile $SchemaPath -ErrorAction Stop)) {
                throw 'Schema validation returned false.'
            }
        }
        catch {
            throw 'The deployment validation report does not satisfy its schema.'
        }
        [System.IO.File]::WriteAllText($temporaryPath, $json + "`n", [System.Text.UTF8Encoding]::new($false))
        $cursor = $root
        foreach ($segment in $OutputPath -split '[\\/]') {
            $cursor = Join-Path $cursor $segment
            if ((Test-Path -LiteralPath $cursor) -and
                ((Get-Item -LiteralPath $cursor).Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                throw 'OutputPath became a symbolic link or reparse point before the report could be committed.'
            }
        }
        Move-Item -LiteralPath $temporaryPath -Destination $target -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }

    return [System.IO.Path]::GetRelativePath($root, $target).Replace([System.IO.Path]::DirectorySeparatorChar, '/')
}

function Write-AzdValidationSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object] $Report)

    $safeReport = [pscustomobject] (ConvertTo-AzdSafeData -Value $Report)
    foreach ($check in $safeReport.checks) {
        $prefix = '[{0}]' -f $check.status.ToUpperInvariant()
        Write-Host ('{0} {1}: {2}' -f $prefix, $check.id, $check.summary)
    }
    Write-Host ('Outcome: {0}; pass={1}, fail={2}, warning={3}, info={4}, skipped={5}, planned={6}' -f `
        $safeReport.outcome, $safeReport.summary.pass, $safeReport.summary.fail, $safeReport.summary.warning,
        $safeReport.summary.info, $safeReport.summary.skipped, $safeReport.summary.planned)
}

function Assert-AzdValidationSucceeded {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object] $Report)

    if ([string] $Report.outcome -notin 'planned', 'passed', 'passedWithWarnings', 'failed') {
        throw 'Deployment validation report has an invalid outcome.'
    }
    if ($Report.outcome -eq 'failed') {
        throw "Deployment validation failed with $($Report.summary.fail) failed check(s)."
    }
}

Export-ModuleMember -Function @(
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
