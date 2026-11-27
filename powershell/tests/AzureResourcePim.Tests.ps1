param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '../..'))

BeforeAll {
    $root = Join-Path $RepositoryRoot 'powershell'
    foreach ($relative in @(
        'src/Common/Encoding.ps1',
        'src/Common/Values.ps1',
        'src/Common/Process.ps1',
        'src/Common/Cookies.ps1',
        'src/Common/Credential.ps1',
        'src/Local/PrivateKey.ps1',
        'src/Local/Signing.ps1',
        'src/KeyVault/Reference.ps1',
        'src/KeyVault/Token.ps1',
        'src/KeyVault/Signing.ps1',
        'src/WebAuthn/AuthenticatorData.ps1',
        'src/WebAuthn/Assertion.ps1',
        'src/Entra/LoginRequest.ps1',
        'src/Entra/LoginInput.ps1',
        'src/Entra/LoginAssertion.ps1',
        'src/Entra/LoginInterrupt.ps1',
        'src/Entra/LoginResult.ps1',
        'src/Public/Invoke-EntraPasskeyLogin.ps1',
        'src/Entra/LoginToken.ps1',
        'src/Public/Get-EntraPasskeyAccessTokenViaDeviceCode.ps1',
        'src/Azure/ResourcePimTransport.ps1',
        'src/Azure/ResourcePim.ps1',
        'src/Public/Get-AzureResourcePimEligibility.ps1',
        'src/Public/Get-AzureResourcePimPolicy.ps1',
        'src/Public/Request-AzureResourcePimActivation.ps1',
        'src/Public/Get-AzureResourcePimRequestStatus.ps1'
    )) {
        . (Join-Path $root $relative)
    }

    function New-SyntheticArmJwt {
        param(
            [string]$TenantId = '11111111-1111-1111-1111-111111111111',
            [string]$PrincipalId = '22222222-2222-2222-2222-222222222222',
            [string]$Acrs = '',
            [long]$IatOffsetSeconds = -30,
            [Nullable[long]]$AuthTimeOffsetSeconds = $null,
            [switch]$IncludeEntraNbfSkew
        )
        $nowUnix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $claims = @{
            aud = 'https://management.azure.com/'
            tid = $TenantId
            oid = $PrincipalId
            amr = @('fido', 'mfa')
            iat = ($nowUnix + $IatOffsetSeconds)
            exp = [DateTimeOffset]::UtcNow.AddMinutes(30).ToUnixTimeSeconds()
        }
        if ($IncludeEntraNbfSkew) {
            $claims.nbf = $claims.iat
        }
        if ($null -ne $AuthTimeOffsetSeconds) {
            $claims.auth_time = ($nowUnix + $AuthTimeOffsetSeconds.Value)
        }
        if ($Acrs) {
            $claims.acrs = @($Acrs)
        }
        $encoded = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes(($claims | ConvertTo-Json -Compress)))
        return "e30.$encoded.c2ln"
    }

    function New-SyntheticPolicyAssignment {
        param(
            [Parameter(Mandatory)][string]$Scope,
            [Parameter(Mandatory)][string]$RoleDefinitionId,
            [Parameter(Mandatory)][string]$RoleName,
            [Parameter(Mandatory)][bool]$IsApprovalRequired,
            [string]$MaximumDuration = 'PT1H',
            [string]$AuthContextClaim = '',
            [bool]$RequireTicketing = $false
        )
        $enabledRules = @('MultiFactorAuthentication', 'Justification')
        if ($RequireTicketing) { $enabledRules += 'Ticketing' }
        $rules = @(
            @{
                id       = 'Approval_EndUser_Assignment'
                ruleType = 'RoleManagementPolicyApprovalRule'
                target   = @{ caller = 'EndUser'; operations = @('All'); level = 'Assignment' }
                setting  = @{
                    isApprovalRequired             = $IsApprovalRequired
                    isApprovalRequiredForExtension = $false
                    isRequestorJustificationRequired = $true
                    approvalMode                   = 'SingleStage'
                    approvalStages                 = @(
                        @{
                            approvalStageTimeOutInDays      = 1
                            isApproverJustificationRequired = $true
                            primaryApprovers                = @(
                                @{ objectId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; userType = 'User'; displayName = 'Synthetic Approver' }
                            )
                        }
                    )
                }
            },
            @{
                id                   = 'Expiration_EndUser_Assignment'
                ruleType             = 'RoleManagementPolicyExpirationRule'
                target               = @{ caller = 'EndUser'; operations = @('All'); level = 'Assignment' }
                isExpirationRequired = $true
                maximumDuration      = $MaximumDuration
            },
            @{
                id           = 'Enablement_EndUser_Assignment'
                ruleType     = 'RoleManagementPolicyEnablementRule'
                target       = @{ caller = 'EndUser'; operations = @('All'); level = 'Assignment' }
                enabledRules = $enabledRules
            },
            @{
                id         = 'AuthenticationContext_EndUser_Assignment'
                ruleType   = 'RoleManagementPolicyAuthenticationContextRule'
                target     = @{ caller = 'EndUser'; operations = @('All'); level = 'Assignment' }
                isEnabled  = (-not [string]::IsNullOrWhiteSpace($AuthContextClaim))
                claimValue = $AuthContextClaim
            }
        )
        return @{
            id         = "$Scope/providers/Microsoft.Authorization/roleManagementPolicyAssignments/policy-1"
            name       = 'policy-1'
            properties = @{
                scope              = $Scope
                roleDefinitionId   = $RoleDefinitionId
                policyId           = "$Scope/providers/Microsoft.Authorization/roleManagementPolicies/pol-1"
                effectiveRules     = $rules
                expandedProperties = @{
                    roleDefinition = @{
                        id          = $RoleDefinitionId
                        displayName = $RoleName
                        type        = 'BuiltInRole'
                    }
                }
            }
        }
    }
}

Describe 'Generated Azure PIM artifacts, entrypoints, and boundaries' {
    It 'keeps all four generated PIM scripts self-contained and matching source version' {
        foreach ($name in @(
            'Get-AzureResourcePimEligibility',
            'Get-AzureResourcePimPolicy',
            'Request-AzureResourcePimActivation',
            'Get-AzureResourcePimRequestStatus'
        )) {
            $path = Join-Path $RepositoryRoot "powershell/scripts/entra/reference/$name.ps1"
            Test-Path -LiteralPath $path | Should -BeTrue
            $text = Get-Content -LiteralPath $path -Raw
            $text | Should -Match '^#Requires -Version 7\.6'
            $text | Should -Match 'Generated by build/build\.ps1'
            $text | Should -Not -Match 'Import-Module|Invoke-Expression'
            $text | Should -Not -Match '[''"]AdminAssign[''"]|/roleAssignmentApprovals'
            $tokens = $null; $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
            $errors.Count | Should -Be 0
            $help = Get-Help $path -ErrorAction Stop
            $help.Synopsis | Should -Not -BeNullOrEmpty
        }
    }

    It 'keeps PIM entrypoints bounded to param block and single command invocation' {
        foreach ($name in @(
            'Get-AzureResourcePimEligibility',
            'Get-AzureResourcePimPolicy',
            'Request-AzureResourcePimActivation',
            'Get-AzureResourcePimRequestStatus'
        )) {
            $path = Join-Path $RepositoryRoot "powershell/entrypoints/$name.ps1"
            $text = Get-Content -LiteralPath $path -Raw
            $tail = ($text -split '# Invoke public command', 2)[1].Trim()
            $tail | Should -BeExactly "$name @PSBoundParameters"
        }
    }

    It 'refuses non-ARM URIs and malformed scopes before network calls' {
        { Assert-AzureArmUri -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests' } | Should -Throw '*untrusted*'
        { Resolve-AzurePimScope -Scope '/subscriptions/sub-1?foo=bar' } | Should -Throw '*scope*'
        { Resolve-AzurePimScope -Scope '/subscriptions/../etc/passwd' } | Should -Throw '*scope*'
        Resolve-AzurePimScope -Scope ' /subscriptions/44444444-4444-4444-4444-444444444444/ ' | Should -BeExactly '/subscriptions/44444444-4444-4444-4444-444444444444'
    }

    It 'masks bearer tokens in sanitized ARM errors and honors -WhatIf with zero auth or network' {
        Mock Get-EntraPasskeyAccessTokenViaDeviceCode { throw 'No token call permitted under -WhatIf.' }
        Mock Invoke-AzureResourcePimHttpRequest { throw 'No HTTP call permitted under -WhatIf.' }

        $sanitized = Get-AzurePimSanitizedArmError -StatusCode 401 -Content '{"error":{"code":"InvalidToken","message":"Rejected Bearer secret.jwt.token and eyJaaaaaaaaaa.bbbbbbbbbbb.cccccccccc"}}'
        $sanitized | Should -Not -Match 'secret\.jwt\.token'
        $sanitized | Should -Not -Match 'eyJaaaaaaaaaa'
        $sanitized | Should -Match '\[REDACTED\]'

        Request-AzureResourcePimActivation `
            -KeyFilePath 'dummy.json' `
            -Scope '/providers/Microsoft.Management/managementGroups/55555555-5555-5555-5555-555555555555' `
            -RoleName 'Owner' `
            -Duration 'PT1H' `
            -Justification 'Offline WhatIf check' `
            -WhatIf

        Should -Invoke Get-EntraPasskeyAccessTokenViaDeviceCode -Times 0 -Exactly
        Should -Invoke Invoke-AzureResourcePimHttpRequest -Times 0 -Exactly
    }
}

Describe 'Azure Resource PIM eligibility discovery and validation' {
    BeforeEach {
        $script:armToken = New-SyntheticArmJwt
        $script:tokenCalls = 0
        Mock Get-EntraPasskeyAccessTokenViaDeviceCode {
            $script:tokenCalls++
            if (@($Scope) -ne @('https://management.azure.com/.default')) {
                throw "Expected ARM scope, got: $($Scope -join ',')"
            }
            [pscustomobject]@{
                Success     = $true
                AccessToken = (ConvertTo-SecureString -String $script:armToken -AsPlainText -Force)
            }
        }
    }

    It 'discovers, paginates, validates, and extracts scheduleId and condition using one ARM token' {
        $mgScope = '/providers/Microsoft.Management/managementGroups/mg-root-synthetic'
        $ownerRoleId = '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
        $schedGuid = '66666666-6666-6666-6666-666666666666'

        Mock Invoke-AzureResourcePimHttpRequest {
            if ($Uri -eq 'https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?$filter=asTarget()&api-version=2020-10-01') {
                return [pscustomobject]@{
                    StatusCode      = 200
                    WwwAuthenticate = @()
                    RequestId       = 'req-1'
                    Content         = (@{
                        value    = @(
                            @{
                                name       = "${schedGuid}_inst1"
                                id         = "$mgScope/providers/Microsoft.Authorization/roleEligibilityScheduleInstances/${schedGuid}_inst1"
                                properties = @{
                                    scope                     = $mgScope
                                    roleDefinitionId          = $ownerRoleId
                                    principalId               = '22222222-2222-2222-2222-222222222222'
                                    roleEligibilityScheduleId = "$mgScope/providers/Microsoft.Authorization/roleEligibilitySchedules/$schedGuid"
                                    memberType                = 'Direct'
                                    status                    = 'Provisioned'
                                    startDateTime             = [DateTimeOffset]::UtcNow.AddDays(-1).ToString('o')
                                    endDateTime               = [DateTimeOffset]::UtcNow.AddDays(30).ToString('o')
                                    condition                 = "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:ContainerName] StringEqualsIgnoreCase 'audit'"
                                    conditionVersion          = '2.0'
                                    expandedProperties        = @{
                                        scope          = @{ id = $mgScope; displayName = 'Root Synthetic MG'; type = 'managementgroup' }
                                        roleDefinition = @{ id = $ownerRoleId; displayName = 'Owner'; type = 'BuiltInRole' }
                                    }
                                }
                            }
                        )
                        nextLink = 'https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?$filter=asTarget()&api-version=2020-10-01&skiptoken=page2'
                    } | ConvertTo-Json -Depth 12 -Compress)
                }
            }
            if ($Uri -like '*skiptoken=page2') {
                return [pscustomobject]@{
                    StatusCode      = 200
                    WwwAuthenticate = @()
                    RequestId       = 'req-2'
                    Content         = '{"value":[]}'
                }
            }
            throw "Unexpected URI: $Uri"
        }

        $res = Get-AzureResourcePimEligibility -KeyFilePath 'dummy.json' -RoleName 'Owner' -Validate -RequireSingle
        $script:tokenCalls | Should -Be 1
        $res.ScheduleId | Should -BeExactly $schedGuid
        $res.Scope | Should -BeExactly $mgScope
        $res.RoleName | Should -BeExactly 'Owner'
        $res.HasCondition | Should -BeTrue
        $res.ConditionVersion | Should -BeExactly '2.0'
        $res.IsValid | Should -BeTrue
        ($res | ConvertTo-Json -Depth 5) | Should -Not -Match ([regex]::Escape($script:armToken))
    }

    It 'rejects expired or non-Provisioned eligibilities when -Validate is set' {
        Mock Invoke-AzureResourcePimHttpRequest {
            [pscustomobject]@{
                StatusCode      = 200
                WwwAuthenticate = @()
                RequestId       = 'req-exp'
                Content         = (@{
                    value = @(
                        @{
                            name       = '77777777-7777-7777-7777-777777777777'
                            properties = @{
                                scope            = '/subscriptions/44444444-4444-4444-4444-444444444444'
                                roleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
                                principalId      = '22222222-2222-2222-2222-222222222222'
                                status           = 'Expired'
                                endDateTime      = [DateTimeOffset]::UtcNow.AddDays(-2).ToString('o')
                                expandedProperties = @{ roleDefinition = @{ displayName = 'Owner' } }
                            }
                        }
                    )
                } | ConvertTo-Json -Depth 10 -Compress)
            }
        }

        { Get-AzureResourcePimEligibility -KeyFilePath 'dummy.json' -RoleName 'Owner' -Validate } | Should -Throw '*failed validation*'
    }
}

Describe 'Azure Resource PIM policy checks and parent-vs-child safety guard' {
    BeforeEach {
        $script:mgScope = '/providers/Microsoft.Management/managementGroups/88888888-8888-8888-8888-888888888888'
        $script:childSubScope = '/subscriptions/99999999-9999-9999-9999-999999999999'
        $script:roleGuid = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
        $script:schedGuid = '66666666-6666-6666-6666-666666666666'
        $script:armToken = New-SyntheticArmJwt
        $script:tokenCalls = 0
        $script:httpCalls = [System.Collections.Generic.List[string]]::new()

        Mock Get-EntraPasskeyAccessTokenViaDeviceCode {
            $script:tokenCalls++
            [pscustomobject]@{
                Success     = $true
                AccessToken = (ConvertTo-SecureString -String $script:armToken -AsPlainText -Force)
            }
        }
    }

    It 'inspects exact child scope policy without falling back to parent scope approval settings' {
        Mock Invoke-AzureResourcePimHttpRequest {
            $script:httpCalls.Add("$Method $Uri")
            if ($Uri -eq "https://management.azure.com$($script:mgScope)/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version=2020-10-01") {
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'p1'
                    Content    = (@{ value = @((New-SyntheticPolicyAssignment -Scope $script:mgScope -RoleDefinitionId "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)" -RoleName 'Owner' -IsApprovalRequired $true -AuthContextClaim 'c3')) } | ConvertTo-Json -Depth 16 -Compress)
                }
            }
            if ($Uri -eq "https://management.azure.com$($script:childSubScope)/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version=2020-10-01") {
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'p2'
                    Content    = (@{ value = @((New-SyntheticPolicyAssignment -Scope $script:childSubScope -RoleDefinitionId "$($script:childSubScope)/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)" -RoleName 'Owner' -IsApprovalRequired $false -MaximumDuration 'PT8H')) } | ConvertTo-Json -Depth 16 -Compress)
                }
            }
            throw "Unexpected URI: $Uri"
        }

        $rootPolicy = Get-AzureResourcePimPolicy -KeyFilePath 'dummy.json' -Scope $script:mgScope -RoleName 'Owner' -RequireApproval
        $rootPolicy.Scope | Should -BeExactly $script:mgScope
        $rootPolicy.IsApprovalRequired | Should -BeTrue
        $rootPolicy.IsAuthenticationContextRequired | Should -BeTrue
        $rootPolicy.AuthenticationContextClaimValue | Should -BeExactly 'c3'

        $childPolicy = Get-AzureResourcePimPolicy -KeyFilePath 'dummy.json' -Scope $script:childSubScope -RoleName 'Owner'
        $childPolicy.Scope | Should -BeExactly $script:childSubScope
        $childPolicy.IsApprovalRequired | Should -BeFalse
        $childPolicy.MaximumDuration | Should -BeExactly 'PT8H'

        { Get-AzureResourcePimPolicy -KeyFilePath 'dummy.json' -Scope $script:childSubScope -RoleName 'Owner' -RequireApproval } | Should -Throw '*does not require approval*'
    }

    It 'refuses activation on unapproved child scope even when parent eligibility scope requires approval' {
        Mock Invoke-AzureResourcePimHttpRequest {
            $script:httpCalls.Add("$Method $Uri")
            if ($Uri -like '*/roleEligibilityScheduleInstances*') {
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'e1'
                    Content    = (@{
                        value = @(
                            @{
                                name       = "$($script:schedGuid)_inst1"
                                properties = @{
                                    scope                     = $script:mgScope
                                    roleDefinitionId          = "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)"
                                    principalId               = '22222222-2222-2222-2222-222222222222'
                                    roleEligibilityScheduleId = "$($script:mgScope)/providers/Microsoft.Authorization/roleEligibilitySchedules/$($script:schedGuid)"
                                    status                    = 'Provisioned'
                                    expandedProperties        = @{
                                        scope          = @{ id = $script:mgScope; displayName = 'Synthetic Root MG'; type = 'managementgroup' }
                                        roleDefinition = @{ id = "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)"; displayName = 'Owner' }
                                    }
                                }
                            }
                        )
                    } | ConvertTo-Json -Depth 12 -Compress)
                }
            }
            if ($Uri -eq "https://management.azure.com$($script:childSubScope)/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version=2020-10-01") {
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'p-child'
                    Content    = (@{ value = @((New-SyntheticPolicyAssignment -Scope $script:childSubScope -RoleDefinitionId "$($script:childSubScope)/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)" -RoleName 'Owner' -IsApprovalRequired $false)) } | ConvertTo-Json -Depth 16 -Compress)
                }
            }
            throw "Unexpected call (validate/PUT or parent policy should not be called): $Method $Uri"
        }

        {
            Request-AzureResourcePimActivation `
                -KeyFilePath 'dummy.json' `
                -Scope $script:childSubScope `
                -RoleName 'Owner' `
                -Duration 'PT1H' `
                -Justification 'Attempt child activation while parent requires approval'
        } | Should -Throw '*does not require approval*'

        $script:tokenCalls | Should -Be 1
        @($script:httpCalls | Where-Object { $_ -like 'POST *' -or $_ -like 'PUT *' }).Count | Should -Be 0
        @($script:httpCalls | Where-Object { $_ -like "*$($script:mgScope)*roleManagementPolicyAssignments*" }).Count | Should -Be 0
    }
}

Describe 'Azure Resource PIM claims challenge, validation, submission, condition preservation, and status transitions' {
    BeforeEach {
        $script:mgScope = '/providers/Microsoft.Management/managementGroups/88888888-8888-8888-8888-888888888888'
        $script:roleGuid = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
        $script:schedGuid = '66666666-6666-6666-6666-666666666666'
        $script:requestGuid = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        $script:approvalGuid = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        $script:targetScheduleGuid = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
        $script:initialToken = New-SyntheticArmJwt
        $script:stepUpToken = New-SyntheticArmJwt -Acrs 'c3'
        $script:expectedClaimsJson = '{"access_token":{"acrs":{"essential":true,"value":"c3"}}}'
        $script:claimsBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($script:expectedClaimsJson))
        $script:acquiredClaims = [System.Collections.Generic.List[object]]::new()
        $script:capturedValidateBody = $null
        $script:capturedPutBody = $null
        $script:capturedTokensUsed = [System.Collections.Generic.List[string]]::new()

        Mock Get-EntraPasskeyAccessTokenViaDeviceCode {
            $script:acquiredClaims.Add($Claims)
            if ($Claims -eq $script:expectedClaimsJson) {
                return [pscustomobject]@{
                    Success     = $true
                    AccessToken = (ConvertTo-SecureString -String $script:stepUpToken -AsPlainText -Force)
                }
            }
            return [pscustomobject]@{
                Success     = $true
                AccessToken = (ConvertTo-SecureString -String $script:initialToken -AsPlainText -Force)
            }
        }
    }

    It 'handles ARM c3 claims challenge cleanly, preserves condition, validates before submitting, and reuses fresh token for PUT' {
        $abacCondition = "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:ContainerName] StringEqualsIgnoreCase 'pim-test'"

        Mock Invoke-AzureResourcePimHttpRequest {
            $plainToken = ConvertTo-PlainTextValue $AccessToken
            $script:capturedTokensUsed.Add("$Method|$Uri|$plainToken")

            if ($Uri -like '*/roleEligibilityScheduleInstances*') {
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'elig-1'
                    Content    = (@{
                        value = @(
                            @{
                                name       = "$($script:schedGuid)_inst1"
                                properties = @{
                                    scope                     = $script:mgScope
                                    roleDefinitionId          = "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)"
                                    principalId               = '22222222-2222-2222-2222-222222222222'
                                    roleEligibilityScheduleId = "$($script:mgScope)/providers/Microsoft.Authorization/roleEligibilitySchedules/$($script:schedGuid)"
                                    memberType                = 'Direct'
                                    status                    = 'Provisioned'
                                    condition                 = $abacCondition
                                    conditionVersion          = '2.0'
                                    expandedProperties        = @{
                                        scope          = @{ id = $script:mgScope; displayName = 'Synthetic Root MG'; type = 'managementgroup' }
                                        roleDefinition = @{ id = "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)"; displayName = 'Owner' }
                                    }
                                }
                            }
                        )
                    } | ConvertTo-Json -Depth 12 -Compress)
                }
            }

            if ($Uri -like '*/roleManagementPolicyAssignments*') {
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'pol-1'
                    Content    = (@{ value = @((New-SyntheticPolicyAssignment -Scope $script:mgScope -RoleDefinitionId "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)" -RoleName 'Owner' -IsApprovalRequired $true -MaximumDuration 'PT1H' -AuthContextClaim 'c3')) } | ConvertTo-Json -Depth 16 -Compress)
                }
            }

            if ($Method -eq 'POST' -and $Uri -like '*/roleAssignmentScheduleRequests/*/validate*') {
                if ($plainToken -eq $script:initialToken) {
                    return [pscustomobject]@{
                        StatusCode      = 401
                        WwwAuthenticate = @("Bearer authorization_uri=`"https://login.microsoftonline.com/$($script:mgScope)`", error=`"insufficient_claims`", claims=`"$($script:claimsBase64)`"")
                        RequestId       = 'val-401'
                        Content         = '{"error":{"code":"InsufficientClaims","message":"Conditional Access authentication context required."}}'
                    }
                }
                if ($plainToken -ne $script:stepUpToken) {
                    throw 'Expected step-up c3 token on /validate retry.'
                }
                $script:capturedValidateBody = $Body | ConvertFrom-Json -AsHashtable
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'val-200'
                    Content    = (@{ id = "$($script:mgScope)/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/$($script:requestGuid)"; name = $script:requestGuid; properties = $script:capturedValidateBody.properties } | ConvertTo-Json -Depth 12 -Compress)
                }
            }

            if ($Method -eq 'PUT' -and $Uri -like '*/roleAssignmentScheduleRequests/*') {
                if ($plainToken -ne $script:stepUpToken) {
                    throw 'Expected PUT to reuse fresh step-up ARM token.'
                }
                $script:capturedPutBody = $Body | ConvertFrom-Json -AsHashtable
                return [pscustomobject]@{
                    StatusCode = 201; WwwAuthenticate = @(); RequestId = 'put-201'
                    Content    = (@{
                        id         = "$($script:mgScope)/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/$($script:requestGuid)"
                        name       = $script:requestGuid
                        properties = @{
                            scope                           = $script:mgScope
                            roleDefinitionId                = $script:capturedPutBody.properties.roleDefinitionId
                            principalId                     = $script:capturedPutBody.properties.principalId
                            requestType                     = 'SelfActivate'
                            linkedRoleEligibilityScheduleId = $script:schedGuid
                            approvalId                      = $script:approvalGuid
                            status                          = 'PendingApprovalProvisioning'
                            justification                   = $script:capturedPutBody.properties.justification
                            condition                       = $script:capturedPutBody.properties.condition
                            conditionVersion                = $script:capturedPutBody.properties.conditionVersion
                            scheduleInfo                    = $script:capturedPutBody.properties.scheduleInfo
                            expandedProperties              = @{
                                roleDefinition = @{ id = $script:capturedPutBody.properties.roleDefinitionId; displayName = 'Owner' }
                            }
                        }
                    } | ConvertTo-Json -Depth 12 -Compress)
                }
            }

            throw "Unexpected call: $Method $Uri"
        }

        $res = Request-AzureResourcePimActivation `
            -KeyFilePath 'dummy.json' `
            -Scope $script:mgScope `
            -RoleName 'Owner' `
            -Duration 'PT1H' `
            -Justification 'Activate Owner for approved change window' `
            -RequestId $script:requestGuid

        $script:acquiredClaims.Count | Should -Be 2
        $script:acquiredClaims[0] | Should -BeNullOrEmpty
        $script:acquiredClaims[1] | Should -BeExactly $script:expectedClaimsJson

        $res.Success | Should -BeTrue
        $res.Validated | Should -BeTrue
        $res.Submitted | Should -BeTrue
        $res.ClaimsChallengeSatisfied | Should -BeTrue
        $res.RequestId | Should -BeExactly $script:requestGuid
        $res.ApprovalId | Should -BeExactly $script:approvalGuid
        $res.Status | Should -BeExactly 'PendingApprovalProvisioning'
        $res.Scope | Should -BeExactly $script:mgScope
        $res.Duration | Should -BeExactly 'PT1H'
        $res.RequestType | Should -BeExactly 'SelfActivate'
        $res.LinkedRoleEligibilityScheduleId | Should -BeExactly $script:schedGuid
        $res.Condition | Should -BeExactly $abacCondition
        $res.ConditionVersion | Should -BeExactly '2.0'

        $script:capturedValidateBody.properties.requestType | Should -BeExactly 'SelfActivate'
        $script:capturedValidateBody.properties.condition | Should -BeExactly $abacCondition
        $script:capturedPutBody.properties.requestType | Should -BeExactly 'SelfActivate'
        $script:capturedPutBody.properties.condition | Should -BeExactly $abacCondition

        $serializedOut = $res | ConvertTo-Json -Depth 10
        $serializedOut | Should -Not -Match ([regex]::Escape($script:initialToken))
        $serializedOut | Should -Not -Match ([regex]::Escape($script:stepUpToken))
    }

    It 'does not synthesize token claims when ARM fails auth context without a claims challenge' {
        Mock Invoke-AzureResourcePimHttpRequest {
            if ($Uri -like '*/roleEligibilityScheduleInstances*') {
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'e1'
                    Content    = (@{
                        value = @(@{
                            name = "$($script:schedGuid)_inst1"
                            properties = @{
                                scope = $script:mgScope
                                roleDefinitionId = "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)"
                                principalId = '22222222-2222-2222-2222-222222222222'
                                roleEligibilityScheduleId = "$($script:mgScope)/providers/Microsoft.Authorization/roleEligibilitySchedules/$($script:schedGuid)"
                                status = 'Provisioned'
                                expandedProperties = @{ roleDefinition = @{ displayName = 'Owner' } }
                            }
                        })
                    } | ConvertTo-Json -Depth 10 -Compress)
                }
            }
            if ($Uri -like '*/roleManagementPolicyAssignments*') {
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'p1'
                    Content    = (@{ value = @((New-SyntheticPolicyAssignment -Scope $script:mgScope -RoleDefinitionId "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)" -RoleName 'Owner' -IsApprovalRequired $true -AuthContextClaim 'c3')) } | ConvertTo-Json -Depth 16 -Compress)
                }
            }
            if ($Uri -like '*/validate*') {
                return [pscustomobject]@{
                    StatusCode = 403; WwwAuthenticate = @(); RequestId = 'v403'
                    Content    = '{"error":{"code":"RoleAssignmentRequestPolicyValidationFailed","message":"Authentication context mismatch."}}'
                }
            }
            throw "Unexpected PUT after failed /validate: $Method $Uri"
        }

        {
            Request-AzureResourcePimActivation `
                -KeyFilePath 'dummy.json' `
                -Scope $script:mgScope `
                -RoleName 'Owner' `
                -Duration 'PT1H' `
                -Justification 'Test non-synthesizing error path' `
                -RequestId $script:requestGuid
        } | Should -Throw '*RoleAssignmentRequestPolicyValidationFailed*'

        $script:acquiredClaims.Count | Should -Be 1
    }

    It 'refreshes a stale >5m ARM token automatically when passkey credentials exist and rejects stale token-only calls' {
        $staleToken = New-SyntheticArmJwt -Acrs 'c3' -IatOffsetSeconds -650 -IncludeEntraNbfSkew
        $freshToken = New-SyntheticArmJwt -Acrs 'c3' -IatOffsetSeconds -302 -IncludeEntraNbfSkew
        $script:stepUpToken = $freshToken
        $script:seenPutAuth = $null

        Mock Get-EntraPasskeyAccessTokenViaDeviceCode {
            $script:acquiredClaims.Add($Claims)
            [pscustomobject]@{
                Success     = $true
                AccessToken = (ConvertTo-SecureString -String $freshToken -AsPlainText -Force)
            }
        }
        Mock Invoke-AzureResourcePimHttpRequest {
            $plainToken = ConvertTo-PlainTextValue $AccessToken
            if ($Uri -like '*/roleEligibilityScheduleInstances*') {
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'e-age'
                    Content    = (@{
                        value = @(@{
                            name       = "$($script:schedGuid)_inst1"
                            properties = @{
                                scope                     = $script:mgScope
                                roleDefinitionId          = "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)"
                                principalId               = '22222222-2222-2222-2222-222222222222'
                                roleEligibilityScheduleId = "$($script:mgScope)/providers/Microsoft.Authorization/roleEligibilitySchedules/$($script:schedGuid)"
                                status                    = 'Provisioned'
                                expandedProperties        = @{ roleDefinition = @{ displayName = 'Owner' } }
                            }
                        })
                    } | ConvertTo-Json -Depth 10 -Compress)
                }
            }
            if ($Uri -like '*/roleManagementPolicyAssignments*') {
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'p-age'
                    Content    = (@{ value = @((New-SyntheticPolicyAssignment -Scope $script:mgScope -RoleDefinitionId "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)" -RoleName 'Owner' -IsApprovalRequired $true -MaximumDuration 'PT1H' -AuthContextClaim 'c3')) } | ConvertTo-Json -Depth 16 -Compress)
                }
            }
            if ($Method -eq 'POST' -and $Uri -like '*/validate*') {
                if ($plainToken -ne $freshToken) { throw 'Expected freshly re-authenticated token after >5m age check.' }
                return [pscustomobject]@{ StatusCode = 200; WwwAuthenticate = @(); RequestId = 'v-age'; Content = '{"id":"ok"}' }
            }
            if ($Method -eq 'PUT') {
                $script:seenPutAuth = $plainToken
                return [pscustomobject]@{
                    StatusCode = 201; WwwAuthenticate = @(); RequestId = 'put-age'
                    Content    = (@{ name = $script:requestGuid; properties = @{ status = 'PendingApprovalProvisioning'; scope = $script:mgScope; approvalId = $script:approvalGuid; scheduleInfo = @{ expiration = @{ duration = 'PT1H' } } } } | ConvertTo-Json -Depth 10 -Compress)
                }
            }
            throw "Unexpected URI: $Method $Uri"
        }

        # Stale token-only call (no passkey credentials) fails closed before /validate
        {
            Request-AzureResourcePimActivation `
                -AccessToken (ConvertTo-SecureString -String $staleToken -AsPlainText -Force) `
                -Scope $script:mgScope `
                -RoleName 'Owner' `
                -Duration 'PT1H' `
                -Justification 'Stale token only'
        } | Should -Throw '*sign-in frequency window*'
        $script:acquiredClaims.Count | Should -Be 0

        # Stale token + passkey credentials triggers automatic fresh auth before /validate
        $res = Request-AzureResourcePimActivation `
            -KeyFilePath 'dummy.json' `
            -AccessToken (ConvertTo-SecureString -String $staleToken -AsPlainText -Force) `
            -Scope $script:mgScope `
            -RoleName 'Owner' `
            -Duration 'PT1H' `
            -Justification 'Auto-refresh stale token for c3' `
            -RequestId $script:requestGuid

        $script:acquiredClaims.Count | Should -Be 1
        $res.TokenRefreshedForAge | Should -BeTrue
        $script:seenPutAuth | Should -BeExactly $freshToken

        # Fresh token (Entra 300s nbf=iat skew -> age 2s < 300s) is reused without triggering age refresh
        $resFresh = Request-AzureResourcePimActivation `
            -KeyFilePath 'dummy.json' `
            -AccessToken (ConvertTo-SecureString -String $freshToken -AsPlainText -Force) `
            -Scope $script:mgScope `
            -RoleName 'Owner' `
            -Duration 'PT1H' `
            -Justification 'Reuse fresh token' `
            -ValidateOnly `
            -RequestId $script:requestGuid

        $script:acquiredClaims.Count | Should -Be 1
        $resFresh.TokenRefreshedForAge | Should -BeFalse
    }

    It 'supports -ValidateOnly without calling PUT and rejects durations above policy MaximumDuration' {
        Mock Invoke-AzureResourcePimHttpRequest {
            if ($Uri -like '*/roleEligibilityScheduleInstances*') {
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'e1'
                    Content    = (@{
                        value = @(@{
                            name = "$($script:schedGuid)_inst1"
                            properties = @{
                                scope = $script:mgScope
                                roleDefinitionId = "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)"
                                principalId = '22222222-2222-2222-2222-222222222222'
                                roleEligibilityScheduleId = "$($script:mgScope)/providers/Microsoft.Authorization/roleEligibilitySchedules/$($script:schedGuid)"
                                status = 'Provisioned'
                                expandedProperties = @{ roleDefinition = @{ displayName = 'Owner' } }
                            }
                        })
                    } | ConvertTo-Json -Depth 10 -Compress)
                }
            }
            if ($Uri -like '*/roleManagementPolicyAssignments*') {
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'p1'
                    Content    = (@{ value = @((New-SyntheticPolicyAssignment -Scope $script:mgScope -RoleDefinitionId "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)" -RoleName 'Owner' -IsApprovalRequired $true -MaximumDuration 'PT1H')) } | ConvertTo-Json -Depth 16 -Compress)
                }
            }
            if ($Method -eq 'POST' -and $Uri -like '*/validate*') {
                return [pscustomobject]@{ StatusCode = 200; WwwAuthenticate = @(); RequestId = 'v1'; Content = '{"id":"validated-id"}' }
            }
            throw "PUT should not be called: $Method $Uri"
        }

        {
            Request-AzureResourcePimActivation `
                -KeyFilePath 'dummy.json' `
                -Scope $script:mgScope `
                -RoleName 'Owner' `
                -Duration 'PT2H' `
                -Justification 'Exceeds max duration'
        } | Should -Throw '*maximum duration*'

        $valRes = Request-AzureResourcePimActivation `
            -KeyFilePath 'dummy.json' `
            -Scope $script:mgScope `
            -RoleName 'Owner' `
            -Duration 'PT1H' `
            -Justification 'ValidateOnly check' `
            -ValidateOnly `
            -RequestId $script:requestGuid

        $valRes.Validated | Should -BeTrue
        $valRes.Submitted | Should -BeFalse
        $valRes.Status | Should -BeExactly 'Validated'
    }

    It 'reads status transition from PendingApprovalProvisioning to Provisioned and correlates active assignment state' {
        $script:pollStep = 0
        Mock Invoke-AzureResourcePimHttpRequest {
            if ($Uri -like '*/roleAssignmentScheduleInstances*') {
                if ($script:pollStep -eq 1) {
                    return [pscustomobject]@{ StatusCode = 200; WwwAuthenticate = @(); RequestId = 'i1'; Content = '{"value":[]}' }
                }
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'i2'
                    Content    = (@{
                        value = @(
                            @{
                                name       = "$($script:targetScheduleGuid)_active_1"
                                properties = @{
                                    roleAssignmentScheduleId = "$($script:mgScope)/providers/Microsoft.Authorization/roleAssignmentSchedules/$($script:targetScheduleGuid)"
                                    scope                    = $script:mgScope
                                    roleDefinitionId         = "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)"
                                    principalId              = '22222222-2222-2222-2222-222222222222'
                                    assignmentType           = 'Activated'
                                    memberType               = 'Direct'
                                    status                   = 'Provisioned'
                                    startDateTime            = [DateTimeOffset]::UtcNow.AddMinutes(-2).ToString('o')
                                    endDateTime              = [DateTimeOffset]::UtcNow.AddMinutes(58).ToString('o')
                                    expandedProperties       = @{
                                        roleDefinition = @{ id = "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)"; displayName = 'Owner' }
                                    }
                                }
                            }
                        )
                    } | ConvertTo-Json -Depth 12 -Compress)
                }
            }
            if ($Uri -eq "https://management.azure.com$($script:mgScope)/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/$($script:requestGuid)?api-version=2020-10-01") {
                $statusText = if ($script:pollStep -eq 1) { 'PendingApprovalProvisioning' } else { 'Provisioned' }
                return [pscustomobject]@{
                    StatusCode = 200; WwwAuthenticate = @(); RequestId = 'r1'
                    Content    = (@{
                        id         = "$($script:mgScope)/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/$($script:requestGuid)"
                        name       = $script:requestGuid
                        properties = @{
                            scope                          = $script:mgScope
                            roleDefinitionId               = "/providers/Microsoft.Authorization/roleDefinitions/$($script:roleGuid)"
                            principalId                    = '22222222-2222-2222-2222-222222222222'
                            requestType                    = 'SelfActivate'
                            approvalId                     = $script:approvalGuid
                            status                         = $statusText
                            targetRoleAssignmentScheduleId = $script:targetScheduleGuid
                            scheduleInfo                   = @{ expiration = @{ type = 'AfterDuration'; duration = 'PT1H' } }
                            expandedProperties             = @{ roleDefinition = @{ displayName = 'Owner' } }
                        }
                    } | ConvertTo-Json -Depth 12 -Compress)
                }
            }
            throw "Unexpected URI: $Uri"
        }

        $script:pollStep = 1
        $pending = Get-AzureResourcePimRequestStatus -KeyFilePath 'dummy.json' -Scope $script:mgScope -RequestId $script:requestGuid
        $pending.Status | Should -BeExactly 'PendingApprovalProvisioning'
        $pending.ApprovalId | Should -BeExactly $script:approvalGuid
        $pending.Duration | Should -BeExactly 'PT1H'
        $pending.IsActive | Should -BeFalse
        $pending.ActiveAssignment | Should -BeNullOrEmpty

        $script:pollStep = 2
        $provisioned = Get-AzureResourcePimRequestStatus -KeyFilePath 'dummy.json' -Scope $script:mgScope -RequestId $script:requestGuid -IncludeAllActiveAssignments
        $provisioned.Status | Should -BeExactly 'Provisioned'
        $provisioned.IsActive | Should -BeTrue
        $provisioned.ActiveAssignment.AssignmentType | Should -BeExactly 'Activated'
        $provisioned.ActiveAssignment.Status | Should -BeExactly 'Provisioned'
        $provisioned.ActiveAssignments.Count | Should -Be 1
        $script:acquiredClaims.Count | Should -Be 2
        ($provisioned | ConvertTo-Json -Depth 10) | Should -Not -Match ([regex]::Escape($script:initialToken))
    }
}

Describe 'Passkey module execution of Azure Resource PIM commands' {
    BeforeAll {
        $script:passkeyModule = Import-Module (Join-Path $RepositoryRoot 'powershell/modules/Passkey/Passkey.psd1') -PassThru -Global -Force -ErrorAction Stop
    }

    AfterAll {
        Remove-Module Passkey -Force -ErrorAction SilentlyContinue
    }

    It 'exports all four commands and executes eligibility lookup through the compiled module' {
        foreach ($cmd in @(
            'Get-AzureResourcePimEligibility',
            'Get-AzureResourcePimPolicy',
            'Request-AzureResourcePimActivation',
            'Get-AzureResourcePimRequestStatus'
        )) {
            $script:passkeyModule.ExportedFunctions.Keys | Should -Contain $cmd
        }

        $token = New-SyntheticArmJwt
        Mock Get-EntraPasskeyAccessTokenViaDeviceCode -ModuleName Passkey {
            [pscustomobject]@{
                Success     = $true
                AccessToken = (ConvertTo-SecureString -String $token -AsPlainText -Force)
            }
        }
        Mock Invoke-AzureResourcePimHttpRequest -ModuleName Passkey {
            [pscustomobject]@{
                StatusCode = 200; WwwAuthenticate = @(); RequestId = 'm1'
                Content    = '{"value":[]}'
            }
        }

        $jsonOut = Passkey\Get-AzureResourcePimEligibility -KeyFilePath 'dummy.json' -Json
        $jsonOut | Should -BeExactly '[]'
        Should -Invoke Get-EntraPasskeyAccessTokenViaDeviceCode -ModuleName Passkey -Times 1 -Exactly
    }
}
