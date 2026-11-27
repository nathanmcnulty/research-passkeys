function Request-AzureResourcePimActivation {
    <#
    .SYNOPSIS
    Validates and submits an Azure resource-role PIM SelfActivate request using ARM Authorization APIs.
    .DESCRIPTION
    Acquires one ARM token per operation (retrying once via Get-EntraPasskeyAccessTokenViaDeviceCode if
    ARM returns an exact Conditional Access claims challenge), discovers and validates the eligible role
    and schedule ID, checks the effective activation policy at the exact requested -Scope, preserves
    any eligibility condition/conditionVersion, validates via roleAssignmentScheduleRequests/validate, and
    submits a SelfActivate request. Refuses by default when the exact requested scope does not require
    approval unless -AllowUnapprovedActivation is specified. Never approves requests or uses AdminAssign.
    When an authentication context is required by policy, validates that the active ARM token's
    authentication timestamp (auth_time/iat) is within -MaxAuthenticationContextTokenAgeSeconds (default 300s /
    5 minutes for Conditional Access sign-in frequency 'every time') and refreshes via passkey if older.
    Supports -ValidateOnly to stop after ARM /validate and -WhatIf with no auth or network calls.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [PSCustomObject]$CredentialFromPipeline,

        [Parameter(Mandatory = $true)]
        [string]$Scope,

        [Parameter(Mandatory = $true)]
        [string]$Duration,

        [Parameter(Mandatory = $true)]
        [string]$Justification,

        [Parameter(Mandatory = $false)]
        [string]$RoleName,

        [Parameter(Mandatory = $false)]
        [string]$RoleDefinitionId,

        [Parameter(Mandatory = $false)]
        [string]$ScheduleId,

        [Parameter(Mandatory = $false)]
        [string]$DiscoveryScope = '/',

        [Parameter(Mandatory = $false)]
        [string]$PrincipalId,

        [Parameter(Mandatory = $false)]
        [string]$StartDateTime,

        [Parameter(Mandatory = $false)]
        [string]$TicketNumber,

        [Parameter(Mandatory = $false)]
        [string]$TicketSystem,

        [Parameter(Mandatory = $false)]
        [string]$RequestId,

        [Parameter(Mandatory = $false)]
        [switch]$ValidateOnly,

        [Parameter(Mandatory = $false)]
        [switch]$AllowUnapprovedActivation,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 86400)]
        [int]$MaxAuthenticationContextTokenAgeSeconds = 300,

        [Parameter(Mandatory = $false)]
        [object]$AccessToken,

        [Parameter(Mandatory = $false)]
        [string]$KeyFilePath,

        [Alias('UserName')]
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $false)]
        [string]$UserHandle,

        [Alias('CredentialId')]
        [Parameter(Mandatory = $false)]
        $CredentialIdentifier,

        [Parameter(Mandatory = $false)]
        $PrivateKey,

        [Parameter(Mandatory = $false)]
        [string]$RelyingParty = 'login.microsoft.com',

        [Parameter(Mandatory = $false)]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [string]$ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46',

        [Parameter(Mandatory = $false)]
        [string]$Claims,

        [Parameter(Mandatory = $false)]
        [string]$VerificationUri = 'https://login.microsoftonline.com/common/oauth2/deviceauth',

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $false)]
        [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0',

        [Parameter(Mandatory = $false)]
        [string]$Proxy,

        [Parameter(Mandatory = $false)]
        [string]$KeyVaultName,

        [Parameter(Mandatory = $false)]
        [string]$KeyVaultKeyName,

        [Parameter(Mandatory = $false)]
        [string]$KeyVaultAccessToken,

        [Parameter(Mandatory = $false)]
        [string]$KeyVaultClientId,

        [Parameter(Mandatory = $false)]
        [object]$KeyVaultClientSecret,

        [Parameter(Mandatory = $false)]
        [string]$KeyVaultTenantId,

        [Parameter(Mandatory = $false)]
        [switch]$Json
    )
    process {
        $targetScope = Resolve-AzurePimScope -Scope $Scope
        $effectiveDiscoveryScope = Resolve-AzurePimScope -Scope $DiscoveryScope
        $isoDuration = ConvertTo-AzurePimIsoDuration -Duration $Duration
        $trimmedJustification = Normalize-OptionalString $Justification
        if (-not $trimmedJustification) {
            throw 'Justification cannot be empty.'
        }
        if ($RoleDefinitionId) { $null = Get-AzurePimRoleDefinitionGuid -RoleDefinitionId $RoleDefinitionId }
        if (-not (Normalize-OptionalString $RoleName) -and -not (Normalize-OptionalString $RoleDefinitionId) -and -not (Normalize-OptionalString $ScheduleId)) {
            throw 'Specify -RoleName, -RoleDefinitionId, or -ScheduleId to identify the eligible Azure resource role.'
        }
        $normalizedRequestId = Normalize-OptionalString $RequestId
        if ($normalizedRequestId) {
            $parsedReq = [guid]::Empty
            if (-not [guid]::TryParse($normalizedRequestId, [ref]$parsedReq) -or $parsedReq -eq [guid]::Empty) {
                throw 'RequestId must be a nonempty GUID.'
            }
            $normalizedRequestId = $parsedReq.ToString()
        } else {
            $normalizedRequestId = [guid]::NewGuid().ToString()
        }
        $effectiveStart = if (Normalize-OptionalString $StartDateTime) {
            $parsedStart = [DateTimeOffset]::MinValue
            if (-not [DateTimeOffset]::TryParse($StartDateTime, [ref]$parsedStart)) {
                throw "StartDateTime '$StartDateTime' is not a valid ISO 8601 timestamp."
            }
            $parsedStart.ToUniversalTime().ToString('o')
        } else {
            [DateTimeOffset]::UtcNow.ToString('o')
        }

        $roleTargetLabel = (Normalize-OptionalString $RoleName) ?? (Normalize-OptionalString $RoleDefinitionId) ?? (Normalize-OptionalString $ScheduleId)
        if (-not $ValidateOnly -and -not $PSCmdlet.ShouldProcess($targetScope, "Validate and submit SelfActivate PIM request for '$roleTargetLabel' (duration $isoDuration)")) {
            return
        }

        $tokenContext = $null
        try {
            $tokenContext = New-AzurePimTokenContext -BoundParameters $PSBoundParameters -CredentialFromPipeline $CredentialFromPipeline -QuietWarningsToStderr:$Json

            $eligibility = Invoke-AzurePimEligibilityDiscovery `
                -Context $tokenContext `
                -Scope $effectiveDiscoveryScope `
                -RoleName $RoleName `
                -RoleDefinitionId $RoleDefinitionId `
                -ScheduleId $ScheduleId `
                -PrincipalId $PrincipalId `
                -Validate `
                -RequireSingle

            $roleDisplay = $eligibility.RoleName ?? $RoleName ?? $eligibility.RoleDefinitionGuid
            $policy = Resolve-AzurePimActivationPolicy `
                -Context $tokenContext `
                -Scope $targetScope `
                -RoleDefinitionId $eligibility.RoleDefinitionId `
                -RoleName $roleDisplay

            if (-not $policy.IsApprovalRequired -and -not $AllowUnapprovedActivation) {
                throw "Refusing SelfActivate at exact scope '$targetScope' for role '$roleDisplay' because the effective policy at that scope does not require approval (IsApprovalRequired=$($policy.IsApprovalRequired)). Specify -AllowUnapprovedActivation only when immediate activation without approval is explicitly intended."
            }

            if ($policy.MaximumDuration) {
                $requestedSpan = [System.Xml.XmlConvert]::ToTimeSpan($isoDuration)
                $maxSpan = [System.Xml.XmlConvert]::ToTimeSpan($policy.MaximumDuration)
                if ($requestedSpan -gt $maxSpan) {
                    throw "Requested duration '$isoDuration' exceeds the effective policy maximum duration '$($policy.MaximumDuration)' at scope '$targetScope'."
                }
            }

            $normalizedTicketNumber = Normalize-OptionalString $TicketNumber
            $normalizedTicketSystem = Normalize-OptionalString $TicketSystem
            if ($policy.IsTicketingRequired -and -not $normalizedTicketNumber) {
                throw "Effective policy at scope '$targetScope' requires ticketing information; provide -TicketNumber."
            }

            Assert-AzurePimFreshTokenForAuthenticationContext `
                -Context $tokenContext `
                -Policy $policy `
                -MaxAgeSeconds $MaxAuthenticationContextTokenAgeSeconds

            $callerOid = Get-AzurePimCallerPrincipalIdFromContext -Context $tokenContext
            $effectivePrincipalId = if (Normalize-OptionalString $PrincipalId) {
                Normalize-OptionalString $PrincipalId
            } elseif ($eligibility.MemberType -eq 'Group' -and $callerOid) {
                $callerOid
            } else {
                $eligibility.PrincipalId
            }
            if (-not $effectivePrincipalId) {
                throw 'Unable to determine principalId for SelfActivate request.'
            }

            $effectiveRoleDefId = Get-AzurePimRoleDefinitionResourceId `
                -Scope $targetScope `
                -PolicyRoleDefinitionId $policy.RoleDefinitionId `
                -FallbackRoleDefinitionId $eligibility.RoleDefinitionId

            $requestProperties = [ordered]@{
                principalId                     = $effectivePrincipalId
                roleDefinitionId                = $effectiveRoleDefId
                requestType                     = 'SelfActivate'
                linkedRoleEligibilityScheduleId = $eligibility.ScheduleId
                scheduleInfo                    = [ordered]@{
                    startDateTime = $effectiveStart
                    expiration    = [ordered]@{
                        type     = 'AfterDuration'
                        duration = $isoDuration
                    }
                }
                justification                   = $trimmedJustification
            }
            if ($normalizedTicketNumber -or $normalizedTicketSystem) {
                $ticket = [ordered]@{}
                if ($normalizedTicketNumber) { $ticket['ticketNumber'] = $normalizedTicketNumber }
                if ($normalizedTicketSystem) { $ticket['ticketSystem'] = $normalizedTicketSystem }
                $requestProperties['ticketInfo'] = $ticket
            }
            if ($eligibility.Condition) {
                $requestProperties['condition'] = $eligibility.Condition
                $requestProperties['conditionVersion'] = if ($eligibility.ConditionVersion) { $eligibility.ConditionVersion } else { '2.0' }
            }
            $payload = @{ properties = $requestProperties }

            $validateUri = New-AzurePimArmUri -Scope $targetScope -ProviderPath "roleAssignmentScheduleRequests/$normalizedRequestId/validate" -QueryString 'api-version=2020-10-01'
            $validationResponse = Invoke-AzureResourcePimArmJson -Context $tokenContext -Uri $validateUri -Method 'POST' -Payload $payload
            if ($validationResponse -is [System.Collections.IDictionary]) {
                if ($validationResponse.ContainsKey('isValid') -and $validationResponse['isValid'] -eq $false) {
                    throw "ARM PIM request validation reported isValid=false at scope '$targetScope'."
                }
                if ($validationResponse.ContainsKey('error') -and $null -ne $validationResponse['error']) {
                    throw (Get-AzurePimSanitizedArmError -StatusCode 400 -Content ($validationResponse | ConvertTo-Json -Depth 10 -Compress))
                }
            }

            if ($ValidateOnly) {
                $validatedOutput = [pscustomobject]@{
                    Success                         = $true
                    Validated                       = $true
                    Submitted                       = $false
                    RequestId                       = $normalizedRequestId
                    RequestResourceId               = Normalize-OptionalString ([string]$validationResponse['id'])
                    ApprovalId                      = $null
                    RequestType                     = 'SelfActivate'
                    Status                          = 'Validated'
                    Scope                           = $targetScope
                    EligibilityScope                = $eligibility.Scope
                    RoleDefinitionId                = $effectiveRoleDefId
                    RoleName                        = $roleDisplay
                    LinkedRoleEligibilityScheduleId = $eligibility.ScheduleId
                    PrincipalId                     = $effectivePrincipalId
                    Duration                        = $isoDuration
                    StartDateTime                   = $effectiveStart
                    Justification                   = $trimmedJustification
                    Condition                       = $eligibility.Condition
                    ConditionVersion                = if ($eligibility.Condition) { [string]$requestProperties['conditionVersion'] } else { $null }
                    IsApprovalRequired              = $policy.IsApprovalRequired
                    ClaimsChallengeSatisfied        = [bool]$tokenContext.ClaimsChallengeSatisfied
                    TokenRefreshedForAge            = [bool]$tokenContext.TokenRefreshedForAge
                }
                if ($Json) { return ($validatedOutput | ConvertTo-Json -Depth 10 -Compress) }
                return $validatedOutput
            }

            $submitUri = New-AzurePimArmUri -Scope $targetScope -ProviderPath "roleAssignmentScheduleRequests/$normalizedRequestId" -QueryString 'api-version=2020-10-01'
            $submitResponse = Invoke-AzureResourcePimArmJson -Context $tokenContext -Uri $submitUri -Method 'PUT' -Payload $payload
            $parsedSubmit = ConvertFrom-AzurePimRequestItem -Item $submitResponse

            $submittedOutput = [pscustomobject]@{
                Success                         = $true
                Validated                       = $true
                Submitted                       = $true
                RequestId                       = $parsedSubmit.RequestId ?? $normalizedRequestId
                RequestResourceId               = $parsedSubmit.RequestResourceId
                ApprovalId                      = $parsedSubmit.ApprovalId
                RequestType                     = $parsedSubmit.RequestType ?? 'SelfActivate'
                Status                          = $parsedSubmit.Status
                Scope                           = $parsedSubmit.Scope ?? $targetScope
                EligibilityScope                = $eligibility.Scope
                RoleDefinitionId                = $parsedSubmit.RoleDefinitionId ?? $effectiveRoleDefId
                RoleName                        = $parsedSubmit.RoleName ?? $roleDisplay
                LinkedRoleEligibilityScheduleId = $parsedSubmit.LinkedRoleEligibilityScheduleId ?? $eligibility.ScheduleId
                PrincipalId                     = $parsedSubmit.PrincipalId ?? $effectivePrincipalId
                Duration                        = $parsedSubmit.Duration ?? $isoDuration
                StartDateTime                   = $parsedSubmit.StartDateTime ?? $effectiveStart
                Justification                   = $parsedSubmit.Justification ?? $trimmedJustification
                Condition                       = $parsedSubmit.Condition ?? $eligibility.Condition
                ConditionVersion                = $parsedSubmit.ConditionVersion ?? $(if ($eligibility.Condition) { [string]$requestProperties['conditionVersion'] } else { $null })
                IsApprovalRequired              = $policy.IsApprovalRequired
                ClaimsChallengeSatisfied        = [bool]$tokenContext.ClaimsChallengeSatisfied
                TokenRefreshedForAge            = [bool]$tokenContext.TokenRefreshedForAge
            }
            if ($Json) { return ($submittedOutput | ConvertTo-Json -Depth 10 -Compress) }
            return $submittedOutput
        } finally {
            Clear-AzurePimTokenContext -Context $tokenContext
        }
    }
}
