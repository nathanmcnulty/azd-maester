BeforeDiscovery {
  $repoRoot = Split-Path $PSScriptRoot -Parent
  $grantTargets = @(Get-ChildItem -LiteralPath $repoRoot -Recurse -File -Filter 'Grant-MaesterGraphPermissions.ps1' | ForEach-Object {
    @{ hooksRoot = $_.Directory.FullName; targetName = [IO.Path]::GetRelativePath($repoRoot, $_.FullName) }
  })
}

Describe 'Tenant-bound Maester Graph permission grants: <targetName>' -ForEach $grantTargets {
  BeforeAll {
    Import-Module (Join-Path $hooksRoot 'Maester-SetupHelpers.psm1') -Force
    $global:MaesterGrantTestPath = Join-Path $hooksRoot 'Grant-MaesterGraphPermissions.ps1'
  }

  AfterAll {
    Remove-Module Maester-SetupHelpers -Force -ErrorAction SilentlyContinue
    Remove-Variable MaesterGrantTestPath, MaesterGrantTestState -Scope Global -ErrorAction SilentlyContinue
  }

  BeforeEach {
    $global:MaesterGrantTestState = @{}
    InModuleScope Maester-SetupHelpers {
      $global:MaesterGrantTestState.Tenant = '11111111-1111-4111-8111-111111111111'
      $global:MaesterGrantTestState.Principal = '22222222-2222-4222-8222-222222222222'
      $global:MaesterGrantTestState.Resource = '33333333-3333-4333-8333-333333333333'
      $global:MaesterGrantTestState.Requests = [Collections.Generic.List[object]]::new()
      $global:MaesterGrantTestState.TokenTenants = [Collections.Generic.List[string]]::new()
      $global:MaesterGrantTestState.Assignments = [Collections.Generic.List[object]]::new()
      $global:MaesterGrantTestState.LaterAssignments = @()
      $global:MaesterGrantTestState.NextLink = $null
      $global:MaesterGrantTestState.ListReads = 0
      $global:MaesterGrantTestState.ReadbackVisible = $true
      $global:MaesterGrantTestState.GraphCount = 1
      $global:MaesterGrantTestState.GraphAppId = '00000003-0000-0000-c000-000000000000'
      $global:MaesterGrantTestState.MalformedPage = $false
      $global:MaesterGrantTestState.PageFailure = $false
      $global:MaesterGrantTestState.EndlessPages = $false
      $global:MaesterGrantTestState.RoleNames = @(
        'Directory.Read.All', 'DirectoryRecommendations.Read.All', 'IdentityRiskEvent.Read.All',
        'Policy.Read.All', 'Policy.Read.ConditionalAccess', 'RoleManagement.Read.All',
        'Reports.Read.All', 'UserAuthenticationMethod.Read.All',
        'DeviceManagementConfiguration.Read.All', 'DeviceManagementServiceConfig.Read.All',
        'DeviceManagementManagedDevices.Read.All', 'DeviceManagementRBAC.Read.All',
        'PrivilegedAccess.Read.AzureAD', 'ReportSettings.Read.All', 'RoleEligibilitySchedule.Read.Directory',
        'SecurityIdentitiesHealth.Read.All', 'SecurityIdentitiesSensors.Read.All',
        'SharePointTenantSettings.Read.All', 'ThreatHunting.Read.All', 'Mail.Send'
      )
      $global:MaesterGrantTestState.Roles = @($global:MaesterGrantTestState.RoleNames | ForEach-Object {
        [pscustomobject]@{ id = "role-$_"; value = $_; isEnabled = $true; allowedMemberTypes = @('Application') }
      })
      # Keep the real helper and REST/token forwarding path loaded while the script imports it.
      Mock Import-Module {} -ParameterFilter { $Name -like '*Maester-SetupHelpers.psm1' }
      Mock Start-Sleep {}
      Mock Write-Host {}
      Mock Get-AzCliAccessToken {
        param($Resource, $TenantId)
        $global:MaesterGrantTestState.TokenTenants.Add([string]$TenantId)
        if ($TenantId -eq $global:MaesterGrantTestState.Tenant) { return 'selected-tenant-token' }
        return 'ambient-other-tenant-token'
      }
      Mock Invoke-RestMethod {
        param($Method, $Uri, $Headers, $Body)
        $global:MaesterGrantTestState.Requests.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body; Authorization = $Headers.Authorization })
        if ($Headers.Authorization -ne 'Bearer selected-tenant-token') { throw 'Request used the ambient tenant.' }
        if ($Uri -like '*/organization?*') { return [pscustomobject]@{ value = @([pscustomobject]@{ id = $global:MaesterGrantTestState.Tenant }) } }
        if (([string]$Uri).StartsWith('https://graph.microsoft.com/v1.0/servicePrincipals?')) {
          return [pscustomobject]@{ value = @(for ($i = 0; $i -lt $global:MaesterGrantTestState.GraphCount; $i++) {
            [pscustomobject]@{ id = $global:MaesterGrantTestState.Resource; appId = $global:MaesterGrantTestState.GraphAppId; appRoles = $global:MaesterGrantTestState.Roles }
          }) }
        }
        if ($Method -eq 'POST') {
          $assignment = $Body | ConvertFrom-Json
          if ($global:MaesterGrantTestState.ReadbackVisible) { $global:MaesterGrantTestState.Assignments.Add($assignment) }
          return $assignment
        }
        $global:MaesterGrantTestState.ListReads++
        if ($global:MaesterGrantTestState.MalformedPage) { return [pscustomobject]@{ unexpected = @() } }
        if ($Uri -like '*skiptoken*') {
          if ($global:MaesterGrantTestState.PageFailure) { throw 'Synthetic page two failure.' }
          if ($global:MaesterGrantTestState.EndlessPages) {
            return [pscustomobject]@{ value = @(); '@odata.nextLink' = "https://graph.microsoft.com/v1.0/servicePrincipals/$($global:MaesterGrantTestState.Principal)/appRoleAssignments?`$skiptoken=$($global:MaesterGrantTestState.ListReads)" }
          }
          return [pscustomobject]@{ value = $global:MaesterGrantTestState.LaterAssignments; '@odata.nextLink' = $global:MaesterGrantTestState.NextLink }
        }
        $page = [pscustomobject]@{ value = @($global:MaesterGrantTestState.Assignments.ToArray()) }
        if ($global:MaesterGrantTestState.NextLink) { $page | Add-Member -NotePropertyName '@odata.nextLink' -NotePropertyValue $global:MaesterGrantTestState.NextLink }
        return $page
      }
    }
  }

  It 'binds precheck, lookup, list, POST and readback to the selected tenant despite a different CLI default' {
    InModuleScope Maester-SetupHelpers {
      & $global:MaesterGrantTestPath -TenantId $global:MaesterGrantTestState.Tenant -PrincipalObjectId $global:MaesterGrantTestState.Principal -AppRoleValues 'Directory.Read.All'
      @($global:MaesterGrantTestState.TokenTenants | Where-Object { $_ -ne $global:MaesterGrantTestState.Tenant }).Count | Should -Be 0
      $global:MaesterGrantTestState.TokenTenants.Count | Should -Be 5
      @($global:MaesterGrantTestState.Requests | Where-Object Method -eq 'POST').Count | Should -Be 1
      $global:MaesterGrantTestState.ListReads | Should -Be 2
      $body = ($global:MaesterGrantTestState.Requests | Where-Object Method -eq 'POST').Body | ConvertFrom-Json
      $body.principalId | Should -Be $global:MaesterGrantTestState.Principal
      $body.resourceId | Should -Be $global:MaesterGrantTestState.Resource
      $body.appRoleId | Should -Be 'role-Directory.Read.All'
    }
  }

  It 'finds an exact grant on a later page without posting a duplicate' {
    InModuleScope Maester-SetupHelpers {
      $global:MaesterGrantTestState.NextLink = "https://graph.microsoft.com/v1.0/servicePrincipals/$($global:MaesterGrantTestState.Principal)/appRoleAssignments?`$skiptoken=page2"
      $global:MaesterGrantTestState.LaterAssignments = @([pscustomobject]@{ principalId = $global:MaesterGrantTestState.Principal; resourceId = $global:MaesterGrantTestState.Resource; appRoleId = 'role-Directory.Read.All' })
      Mock Invoke-RestMethod {
        param($Method, $Uri, $Headers)
        $global:MaesterGrantTestState.Requests.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Authorization = $Headers.Authorization })
        if ($Headers.Authorization -ne 'Bearer selected-tenant-token') { throw 'Request used the ambient tenant.' }
        if ($Uri -like '*/organization?*') { return [pscustomobject]@{ value = @() } }
        if (([string]$Uri).StartsWith('https://graph.microsoft.com/v1.0/servicePrincipals?')) { return [pscustomobject]@{ value = @([pscustomobject]@{ id = $global:MaesterGrantTestState.Resource; appId = $global:MaesterGrantTestState.GraphAppId; appRoles = $global:MaesterGrantTestState.Roles }) } }
        if ($Uri -like '*skiptoken*') { return [pscustomobject]@{ value = $global:MaesterGrantTestState.LaterAssignments } }
        return [pscustomobject]@{ value = @(); '@odata.nextLink' = $global:MaesterGrantTestState.NextLink }
      }
      & $global:MaesterGrantTestPath -TenantId $global:MaesterGrantTestState.Tenant -PrincipalObjectId $global:MaesterGrantTestState.Principal -AppRoleValues 'Directory.Read.All'
      @($global:MaesterGrantTestState.Requests | Where-Object Method -eq 'POST').Count | Should -Be 0
      $global:MaesterGrantTestState.TokenTenants.Count | Should -Be 4
      @($global:MaesterGrantTestState.TokenTenants | Where-Object { $_ -ne $global:MaesterGrantTestState.Tenant }).Count | Should -Be 0
    }
  }

  It 'rejects unsafe continuation <link> before any POST' -TestCases @(
    @{ link = 'https://other.example/v1.0/servicePrincipals/22222222-2222-4222-8222-222222222222/appRoleAssignments' }
    @{ link = 'http://graph.microsoft.com/v1.0/servicePrincipals/22222222-2222-4222-8222-222222222222/appRoleAssignments' }
    @{ link = 'https://graph.microsoft.com:444/v1.0/servicePrincipals/22222222-2222-4222-8222-222222222222/appRoleAssignments' }
    @{ link = 'https://user@graph.microsoft.com/v1.0/servicePrincipals/22222222-2222-4222-8222-222222222222/appRoleAssignments' }
    @{ link = 'https://graph.microsoft.com/v1.0/servicePrincipals/other/appRoleAssignments' }
    @{ link = '/v1.0/servicePrincipals/22222222-2222-4222-8222-222222222222/appRoleAssignments' }
  ) {
    param($link)
    InModuleScope Maester-SetupHelpers -Parameters @{ link = $link } {
      $global:MaesterGrantTestState.NextLink = $link
      { & $global:MaesterGrantTestPath -TenantId $global:MaesterGrantTestState.Tenant -PrincipalObjectId $global:MaesterGrantTestState.Principal -AppRoleValues 'Directory.Read.All' } | Should -Throw '*expected secure collection*'
      @($global:MaesterGrantTestState.Requests | Where-Object Method -eq 'POST').Count | Should -Be 0
      $global:MaesterGrantTestState.Requests.Count | Should -Be 3
    }
  }

  It 'fails closed for repeated pages, page limits, incomplete responses and page failures' -TestCases @(
    @{ mode = 'loop'; expected = '*repeated a page*' }
    @{ mode = 'limit'; expected = '*exceeded its limit*' }
    @{ mode = 'malformed'; expected = '*missing its value collection*' }
    @{ mode = 'failure'; expected = '*Synthetic page two failure*' }
  ) {
    param($mode, $expected)
    InModuleScope Maester-SetupHelpers -Parameters @{ mode = $mode; expected = $expected } {
      $global:MaesterGrantTestState.NextLink = "https://graph.microsoft.com/v1.0/servicePrincipals/$($global:MaesterGrantTestState.Principal)/appRoleAssignments?`$skiptoken=page2"
      $global:MaesterGrantTestState.EndlessPages = $mode -eq 'limit'
      $global:MaesterGrantTestState.MalformedPage = $mode -eq 'malformed'
      $global:MaesterGrantTestState.PageFailure = $mode -eq 'failure'
      { & $global:MaesterGrantTestPath -TenantId $global:MaesterGrantTestState.Tenant -PrincipalObjectId $global:MaesterGrantTestState.Principal -AppRoleValues 'Directory.Read.All' } | Should -Throw $expected
      @($global:MaesterGrantTestState.Requests | Where-Object Method -eq 'POST').Count | Should -Be 0
      $global:MaesterGrantTestState.ListReads | Should -BeLessOrEqual 100
    }
  }

  It 'preserves <profile> permissions with IncludeMailSend=<mail>' -TestCases @(
    @{ profile = 'Minimal'; mail = $false; count = 8 }
    @{ profile = 'Minimal'; mail = $true; count = 9 }
    @{ profile = 'Extended'; mail = $false; count = 19 }
    @{ profile = 'Extended'; mail = $true; count = 20 }
  ) {
    param($profile, $mail, $count)
    InModuleScope Maester-SetupHelpers -Parameters @{ profile = $profile; mail = $mail; count = $count } {
      & $global:MaesterGrantTestPath -TenantId $global:MaesterGrantTestState.Tenant -PrincipalObjectId $global:MaesterGrantTestState.Principal -PermissionProfile $profile -IncludeMailSend $mail
      $actual = @($global:MaesterGrantTestState.Assignments | ForEach-Object appRoleId | Sort-Object)
      $expected = @($global:MaesterGrantTestState.RoleNames[0..$(if ($profile -eq 'Minimal') { 7 } else { 18 })])
      if ($mail) { $expected += 'Mail.Send' }
      $actual.Count | Should -Be $count
      ($actual -join ',') | Should -Be (($expected | ForEach-Object { "role-$_" } | Sort-Object) -join ',')
    }
  }

  It 'preserves explicit role selection and deduplicates requested values' {
    InModuleScope Maester-SetupHelpers {
      & $global:MaesterGrantTestPath -TenantId $global:MaesterGrantTestState.Tenant -PrincipalObjectId $global:MaesterGrantTestState.Principal -PermissionProfile Extended -AppRoleValues 'Reports.Read.All','Reports.Read.All' -IncludeMailSend $true
      $global:MaesterGrantTestState.Assignments.Count | Should -Be 1
      $global:MaesterGrantTestState.Assignments[0].appRoleId | Should -Be 'role-Reports.Read.All'
    }
  }

  It 'validates all requested roles before posting and rejects disabled roles' -TestCases @(
    @{ disabled = $false }
    @{ disabled = $true }
  ) {
    param($disabled)
    InModuleScope Maester-SetupHelpers -Parameters @{ disabled = $disabled } {
      if ($disabled) { $global:MaesterGrantTestState.Roles[0].isEnabled = $false }
      $roles = if ($disabled) { @('Directory.Read.All') } else { @('Directory.Read.All', 'Unknown.Role') }
      { & $global:MaesterGrantTestPath -TenantId $global:MaesterGrantTestState.Tenant -PrincipalObjectId $global:MaesterGrantTestState.Principal -AppRoleValues $roles } | Should -Throw '*enabled application role*'
      @($global:MaesterGrantTestState.Requests | Where-Object Method -eq 'POST').Count | Should -Be 0
    }
  }

  It 'does not mistake another principal or resource for the requested grant' {
    InModuleScope Maester-SetupHelpers {
      $global:MaesterGrantTestState.Assignments.Add([pscustomobject]@{ principalId = 'other'; resourceId = $global:MaesterGrantTestState.Resource; appRoleId = 'role-Directory.Read.All' })
      $global:MaesterGrantTestState.Assignments.Add([pscustomobject]@{ principalId = $global:MaesterGrantTestState.Principal; resourceId = 'other'; appRoleId = 'role-Directory.Read.All' })
      & $global:MaesterGrantTestPath -TenantId $global:MaesterGrantTestState.Tenant -PrincipalObjectId $global:MaesterGrantTestState.Principal -AppRoleValues 'Directory.Read.All'
      @($global:MaesterGrantTestState.Requests | Where-Object Method -eq 'POST').Count | Should -Be 1
    }
  }

  It 'fails rather than announcing success when exact readback never appears' {
    InModuleScope Maester-SetupHelpers {
      $global:MaesterGrantTestState.ReadbackVisible = $false
      { & $global:MaesterGrantTestPath -TenantId $global:MaesterGrantTestState.Tenant -PrincipalObjectId $global:MaesterGrantTestState.Principal -AppRoleValues 'Directory.Read.All' } | Should -Throw '*could not be verified*'
      $global:MaesterGrantTestState.ListReads | Should -Be 4
      @($global:MaesterGrantTestState.Requests | Where-Object Method -eq 'POST').Count | Should -Be 1
      Should -Invoke Start-Sleep -Times 2 -Exactly
      Should -Invoke Write-Host -Times 0 -ParameterFilter { $Object -eq 'Graph app role assignment completed.' }
    }
  }

  It 'requires a unique Graph service principal before granting' -TestCases @(@{ count = 0 }, @{ count = 2 }) {
    param($count)
    InModuleScope Maester-SetupHelpers -Parameters @{ count = $count } {
      $global:MaesterGrantTestState.GraphCount = $count
      { & $global:MaesterGrantTestPath -TenantId $global:MaesterGrantTestState.Tenant -PrincipalObjectId $global:MaesterGrantTestState.Principal -AppRoleValues 'Directory.Read.All' } | Should -Throw '*Exactly one Microsoft Graph*'
      @($global:MaesterGrantTestState.Requests | Where-Object Method -eq 'POST').Count | Should -Be 0
    }
  }
  It 'rejects a different resource service principal even when the filtered result has one row' {
    InModuleScope Maester-SetupHelpers {
      $global:MaesterGrantTestState.GraphAppId = 'different-application'
      { & $global:MaesterGrantTestPath -TenantId $global:MaesterGrantTestState.Tenant -PrincipalObjectId $global:MaesterGrantTestState.Principal -AppRoleValues 'Directory.Read.All' } | Should -Throw '*not Microsoft Graph*'
      @($global:MaesterGrantTestState.Requests | Where-Object Method -eq 'POST').Count | Should -Be 0
    }
  }

  It 'preserves partial existing grants and reruns without adding duplicates' {
    InModuleScope Maester-SetupHelpers {
      $global:MaesterGrantTestState.Assignments.Add([pscustomobject]@{ principalId = $global:MaesterGrantTestState.Principal; resourceId = $global:MaesterGrantTestState.Resource; appRoleId = 'role-Directory.Read.All' })
      & $global:MaesterGrantTestPath -TenantId $global:MaesterGrantTestState.Tenant -PrincipalObjectId $global:MaesterGrantTestState.Principal -AppRoleValues 'Directory.Read.All','Reports.Read.All'
      & $global:MaesterGrantTestPath -TenantId $global:MaesterGrantTestState.Tenant -PrincipalObjectId $global:MaesterGrantTestState.Principal -AppRoleValues 'Directory.Read.All','Reports.Read.All'
      @($global:MaesterGrantTestState.Requests | Where-Object Method -eq 'POST').Count | Should -Be 1
      $global:MaesterGrantTestState.Assignments.Count | Should -Be 2
    }
  }

}
