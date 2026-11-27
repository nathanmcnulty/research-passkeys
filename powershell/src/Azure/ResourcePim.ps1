function New-AzurePimTokenContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$BoundParameters,
        [AllowNull()][PSCustomObject]$CredentialFromPipeline,
        [switch]$QuietWarningsToStderr
    )
    $explicitToken = $null
    if ($BoundParameters.ContainsKey('AccessToken') -and $null -ne $BoundParameters['AccessToken']) {
        $plainCheck = ConvertTo-PlainTextValue $BoundParameters['AccessToken']
        if ([string]::IsNullOrWhiteSpace($plainCheck)) {
            throw 'AccessToken cannot be empty.'
        }
        $plainCheck = $null
        $explicitToken = $BoundParameters['AccessToken']
    }

    $authParams = @{}
    foreach ($name in @(
        'CredentialFromPipeline', 'KeyFilePath', 'UserPrincipalName', 'UserHandle',
        'CredentialIdentifier', 'PrivateKey', 'RelyingParty', 'TenantId', 'ClientId',
        'VerificationUri', 'TimeoutSeconds', 'UserAgent', 'Proxy',
        'KeyVaultName', 'KeyVaultKeyName', 'KeyVaultAccessToken', 'KeyVaultClientId',
        'KeyVaultClientSecret', 'KeyVaultTenantId'
    )) {
        if ($BoundParameters.ContainsKey($name)) {
            $authParams[$name] = $BoundParameters[$name]
        }
    }
    if (-not $authParams.ContainsKey('CredentialFromPipeline') -and $null -ne $CredentialFromPipeline) {
        $authParams['CredentialFromPipeline'] = $CredentialFromPipeline
    }
    $authParams['Scope'] = @('https://management.azure.com/.default')

    $hasPasskeyInputs = $false
    foreach ($k in @('CredentialFromPipeline', 'KeyFilePath', 'PrivateKey', 'KeyVaultName', 'KeyVaultKeyName')) {
        if ($authParams.ContainsKey($k) -and $null -ne $authParams[$k] -and -not [string]::IsNullOrWhiteSpace([string]$authParams[$k])) {
            $hasPasskeyInputs = $true
            break
        }
    }

    $explicitClaims = if ($BoundParameters.ContainsKey('Claims')) { Normalize-OptionalString ([string]$BoundParameters['Claims']) } else { $null }
    if ($explicitClaims) {
        $authParams['Claims'] = $explicitClaims
    }

    return @{
        AccessToken              = $explicitToken
        AcquiredAtUtc            = if ($explicitToken) { $null } else { $null }
        AuthParameters           = $authParams
        CanStepUp                = $hasPasskeyInputs
        ActiveClaims             = $explicitClaims
        AcquisitionCount         = 0
        ChallengeAttemptCount    = 0
        TokenRefreshedForAge     = $false
        ClaimsChallengeSatisfied = [bool]($explicitToken -and $explicitClaims)
        UserAgent                = if ($BoundParameters.ContainsKey('UserAgent')) { [string]$BoundParameters['UserAgent'] } else { $null }
        Proxy                    = if ($BoundParameters.ContainsKey('Proxy')) { [string]$BoundParameters['Proxy'] } else { $null }
        QuietWarningsToStderr    = [bool]$QuietWarningsToStderr
    }
}

function ConvertFrom-AzurePimTimestamp {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [DateTimeOffset]) {
        return $Value.ToUniversalTime().ToString('o')
    }
    if ($Value -is [datetime]) {
        $utcOffset = if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) {
            [DateTimeOffset]::new([datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc))
        } else {
            [DateTimeOffset]::new($Value.ToUniversalTime())
        }
        return $utcOffset.ToString('o')
    }
    $text = Normalize-OptionalString ([string]$Value)
    if (-not $text) {
        return $null
    }
    $parsed = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$parsed)) {
        return $parsed.ToString('o')
    }
    return $text
}

function Clear-AzurePimTokenContext {
    param([AllowNull()][hashtable]$Context)
    if ($null -eq $Context) {
        return
    }
    $Context.AccessToken = $null
    if ($Context.AuthParameters) {
        if ($Context.AuthParameters.ContainsKey('PrivateKey')) { $Context.AuthParameters['PrivateKey'] = $null }
        if ($Context.AuthParameters.ContainsKey('KeyVaultAccessToken')) { $Context.AuthParameters['KeyVaultAccessToken'] = $null }
        if ($Context.AuthParameters.ContainsKey('KeyVaultClientSecret')) { $Context.AuthParameters['KeyVaultClientSecret'] = $null }
    }
}

function Resolve-AzurePimBearerToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [AllowNull()][string]$ChallengeClaims
    )
    $normalizedChallenge = Normalize-OptionalString $ChallengeClaims
    if ($null -ne $Context.AccessToken -and -not $normalizedChallenge) {
        return $Context.AccessToken
    }

    if ($normalizedChallenge) {
        if (-not $Context.CanStepUp) {
            throw "Azure Resource Manager returned a Conditional Access claims challenge, but no passkey credential parameters were provided to re-authenticate. Challenge claims: $normalizedChallenge"
        }
        if ($Context.ChallengeAttemptCount -ge 2) {
            throw 'Azure Resource Manager repeatedly returned a claims challenge after passkey step-up re-authentication.'
        }
    }

    $invokeParams = @{}
    foreach ($entry in $Context.AuthParameters.GetEnumerator()) {
        $invokeParams[$entry.Key] = $entry.Value
    }
    if ($normalizedChallenge) {
        $invokeParams['Claims'] = $normalizedChallenge
    }
    if ($Context.QuietWarningsToStderr -and -not $invokeParams.ContainsKey('WarningAction')) {
        $invokeParams['WarningAction'] = 'SilentlyContinue'
    }

    $tokenResult = Get-EntraPasskeyAccessTokenViaDeviceCode @invokeParams
    $acquiredToken = if ($tokenResult -is [System.Security.SecureString] -or $tokenResult -is [string]) {
        $tokenResult
    } elseif ($null -ne $tokenResult -and $tokenResult.PSObject.Properties['AccessToken']) {
        $tokenResult.AccessToken
    } else {
        $null
    }

    $plainCheck = ConvertTo-PlainTextValue $acquiredToken
    if ([string]::IsNullOrWhiteSpace($plainCheck)) {
        throw 'Passkey device code helper did not return an Azure Resource Manager access token.'
    }
    $plainCheck = $null

    $Context.AccessToken = $acquiredToken
    $Context.AcquiredAtUtc = [DateTimeOffset]::UtcNow
    $Context.AcquisitionCount = [int]$Context.AcquisitionCount + 1
    if ($normalizedChallenge) {
        $Context.ChallengeAttemptCount = [int]$Context.ChallengeAttemptCount + 1
        $Context.ActiveClaims = $normalizedChallenge
        $Context.ClaimsChallengeSatisfied = $true
    }
    return $Context.AccessToken
}

function Get-AzurePimTokenAuthTimestamp {
    param([Parameter(Mandatory)][hashtable]$Context)
    if ($null -eq $Context.AccessToken) {
        return $null
    }
    $plain = ConvertTo-PlainTextValue $Context.AccessToken
    try {
        $claims = ConvertFrom-EntraJwtPayload -Token $plain
        $authTimeUnix = 0L
        if ($claims -and $claims.ContainsKey('auth_time') -and $null -ne $claims['auth_time'] -and
            [long]::TryParse([string]$claims['auth_time'], [ref]$authTimeUnix) -and $authTimeUnix -gt 0) {
            return [DateTimeOffset]::FromUnixTimeSeconds($authTimeUnix)
        }
        $iatUnix = 0L
        if ($claims -and $claims.ContainsKey('iat') -and $null -ne $claims['iat'] -and
            [long]::TryParse([string]$claims['iat'], [ref]$iatUnix) -and $iatUnix -gt 0) {
            $nbfUnix = 0L
            $hasNbf = $claims.ContainsKey('nbf') -and $null -ne $claims['nbf'] -and [long]::TryParse([string]$claims['nbf'], [ref]$nbfUnix)
            # Microsoft Entra ID access tokens backdate both iat and nbf by 300 seconds for clock skew.
            $effectiveIssuedUnix = if ($hasNbf -and $nbfUnix -eq $iatUnix) { $iatUnix + 300L } else { $iatUnix }
            return [DateTimeOffset]::FromUnixTimeSeconds($effectiveIssuedUnix)
        }
        return $Context.AcquiredAtUtc
    } finally {
        $plain = $null
    }
}

function Assert-AzurePimFreshTokenForAuthenticationContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][pscustomobject]$Policy,
        [int]$MaxAgeSeconds = 300
    )
    if (-not $Policy.IsAuthenticationContextRequired) {
        return
    }
    $authTimestamp = Get-AzurePimTokenAuthTimestamp -Context $Context
    $isStale = $false
    $ageDescription = 'unknown authentication timestamp'
    if ($null -eq $authTimestamp) {
        $isStale = $true
    } else {
        $ageSeconds = ([DateTimeOffset]::UtcNow - $authTimestamp).TotalSeconds
        $ageDescription = "$([int][Math]::Round($ageSeconds))s"
        if ($ageSeconds -ge $MaxAgeSeconds) {
            $isStale = $true
        }
    }

    if (-not $isStale) {
        return
    }

    $ctxLabel = if ($Policy.AuthenticationContextClaimValue) { $Policy.AuthenticationContextClaimValue } else { 'required authentication context' }
    if (-not $Context.CanStepUp) {
        throw "Existing ARM access token authentication age ($ageDescription) exceeds or cannot satisfy the ${MaxAgeSeconds}s sign-in frequency window for authentication context '$ctxLabel'. Provide passkey credentials or acquire a freshly authenticated ARM token."
    }

    Write-Verbose "Existing ARM token age ($ageDescription) exceeds ${MaxAgeSeconds}s for authentication context '$ctxLabel'; acquiring a fresh passkey token."
    $Context.AccessToken = $null
    $Context.AcquiredAtUtc = $null
    $Context.TokenRefreshedForAge = $true
    $null = Resolve-AzurePimBearerToken -Context $Context
}

function Invoke-AzureResourcePimArmJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PUT')][string]$Method,
        [AllowNull()][hashtable]$Payload
    )
    $bodyJson = if ($null -ne $Payload) { $Payload | ConvertTo-Json -Depth 16 -Compress } else { $null }
    $retriedChallenge = $false

    while ($true) {
        $token = Resolve-AzurePimBearerToken -Context $Context
        $response = Invoke-AzureResourcePimHttpRequest `
            -Uri $Uri `
            -Method $Method `
            -AccessToken $token `
            -Body $bodyJson `
            -UserAgent $Context.UserAgent `
            -Proxy $Context.Proxy

        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
            if ([string]::IsNullOrWhiteSpace($response.Content)) {
                return @{}
            }
            try {
                return ($response.Content | ConvertFrom-Json -AsHashtable -ErrorAction Stop)
            } catch {
                throw "Azure Resource Manager returned invalid JSON on HTTP $($response.StatusCode)."
            }
        }

        if ($response.StatusCode -in @(400, 401, 403) -and -not $retriedChallenge) {
            $challenge = Get-AzurePimClaimsChallengeFromResponse -WwwAuthenticate $response.WwwAuthenticate -Content $response.Content
            if ($challenge -and $challenge -cne $Context.ActiveClaims) {
                $retriedChallenge = $true
                $null = Resolve-AzurePimBearerToken -Context $Context -ChallengeClaims $challenge
                continue
            }
        }

        throw (Get-AzurePimSanitizedArmError -StatusCode $response.StatusCode -Content $response.Content -RequestId $response.RequestId)
    }
}

function Invoke-AzureResourcePimPagedGet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$Uri
    )
    $items = [System.Collections.Generic.List[hashtable]]::new()
    $nextUri = $Uri
    for ($page = 0; $page -lt 50 -and -not [string]::IsNullOrWhiteSpace($nextUri); $page++) {
        $null = Assert-AzureArmUri -Uri $nextUri
        $payload = Invoke-AzureResourcePimArmJson -Context $Context -Uri $nextUri -Method 'GET'
        if ($payload -is [System.Collections.IDictionary] -and $payload.ContainsKey('value') -and $null -ne $payload['value']) {
            foreach ($entry in @($payload['value'])) {
                if ($entry -is [System.Collections.IDictionary]) {
                    $items.Add($entry)
                }
            }
        }
        $candidateNext = if ($payload.ContainsKey('nextLink')) { $payload['nextLink'] } elseif ($payload.ContainsKey('@odata.nextLink')) { $payload['@odata.nextLink'] } else { $null }
        $nextUri = Normalize-OptionalString ([string]$candidateNext)
    }
    return @($items)
}

function Get-AzurePimRoleDefinitionGuid {
    param([AllowNull()][string]$RoleDefinitionId)
    $trimmed = Normalize-OptionalString $RoleDefinitionId
    if (-not $trimmed) {
        return $null
    }
    $leaf = ($trimmed.TrimEnd('/') -split '/')[-1]
    $parsed = [guid]::Empty
    if ([guid]::TryParse($leaf, [ref]$parsed) -and $parsed -ne [guid]::Empty) {
        return $parsed.ToString()
    }
    throw "RoleDefinitionId '$RoleDefinitionId' does not end in a valid nonempty GUID."
}

function Get-AzurePimRoleDefinitionResourceId {
    param(
        [Parameter(Mandatory)][string]$Scope,
        [AllowNull()][string]$PolicyRoleDefinitionId,
        [AllowNull()][string]$FallbackRoleDefinitionId
    )
    $policyId = Normalize-OptionalString $PolicyRoleDefinitionId
    if ($policyId) {
        return $policyId
    }
    $guid = Get-AzurePimRoleDefinitionGuid -RoleDefinitionId $FallbackRoleDefinitionId
    if (-not $guid) {
        throw 'A valid RoleDefinitionId is required.'
    }
    $normalizedScope = Resolve-AzurePimScope -Scope $Scope
    if ($normalizedScope -eq '/') {
        return "/providers/Microsoft.Authorization/roleDefinitions/$guid"
    }
    return "$normalizedScope/providers/Microsoft.Authorization/roleDefinitions/$guid"
}

function Get-AzurePimCallerPrincipalIdFromContext {
    param([Parameter(Mandatory)][hashtable]$Context)
    $token = Resolve-AzurePimBearerToken -Context $Context
    $plain = ConvertTo-PlainTextValue $token
    try {
        $claims = ConvertFrom-EntraJwtPayload -Token $plain
        if ($claims -and $claims.ContainsKey('oid')) {
            return Normalize-OptionalString ([string]$claims['oid'])
        }
        return $null
    } finally {
        $plain = $null
    }
}

function Extract-AzurePimEligibilityScheduleId {
    param([Parameter(Mandatory)][hashtable]$Item)
    $props = if ($Item.ContainsKey('properties') -and $Item['properties'] -is [System.Collections.IDictionary]) { $Item['properties'] } else { @{} }
    $rawScheduleRef = Normalize-OptionalString ([string]$props['roleEligibilityScheduleId'])
    if ($rawScheduleRef) {
        $leaf = ($rawScheduleRef.TrimEnd('/') -split '/')[-1]
        if ($leaf) { return $leaf }
    }
    $rawId = Normalize-OptionalString ([string]$Item['id'])
    if ($rawId -and $rawId -match '/roleEligibilitySchedules/([^/?]+)$') {
        return $Matches[1]
    }
    $rawName = Normalize-OptionalString ([string]$Item['name'])
    if ($rawName) {
        if ($rawName -match '^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:_|$)') {
            return $Matches[1]
        }
        return $rawName
    }
    return $null
}

function ConvertFrom-AzurePimEligibilityItem {
    param([Parameter(Mandatory)][hashtable]$Item)
    $props = if ($Item.ContainsKey('properties') -and $Item['properties'] -is [System.Collections.IDictionary]) { $Item['properties'] } else { @{} }
    $expanded = if ($props.ContainsKey('expandedProperties') -and $props['expandedProperties'] -is [System.Collections.IDictionary]) { $props['expandedProperties'] } else { @{} }
    $expScope = if ($expanded.ContainsKey('scope') -and $expanded['scope'] -is [System.Collections.IDictionary]) { $expanded['scope'] } else { @{} }
    $expRole = if ($expanded.ContainsKey('roleDefinition') -and $expanded['roleDefinition'] -is [System.Collections.IDictionary]) { $expanded['roleDefinition'] } else { @{} }
    $expPrincipal = if ($expanded.ContainsKey('principal') -and $expanded['principal'] -is [System.Collections.IDictionary]) { $expanded['principal'] } else { @{} }

    $scheduleId = Extract-AzurePimEligibilityScheduleId -Item $Item
    $rawScope = Normalize-OptionalString ([string]($props['scope'] ?? $expScope['id']))
    $normalizedScope = if ($rawScope) { Resolve-AzurePimScope -Scope $rawScope } else { $null }
    $roleDefId = Normalize-OptionalString ([string]($props['roleDefinitionId'] ?? $expRole['id']))
    $roleDefGuid = if ($roleDefId) {
        try { Get-AzurePimRoleDefinitionGuid -RoleDefinitionId $roleDefId } catch { $null }
    } else {
        $null
    }
    $principalId = Normalize-OptionalString ([string]($props['principalId'] ?? $expPrincipal['id']))
    $status = Normalize-OptionalString ([string]$props['status'])
    $startRaw = ConvertFrom-AzurePimTimestamp $props['startDateTime']
    $endRaw = ConvertFrom-AzurePimTimestamp $props['endDateTime']
    $condition = Normalize-OptionalString ([string]$props['condition'])
    $conditionVersion = Normalize-OptionalString ([string]$props['conditionVersion'])

    $reasons = [System.Collections.Generic.List[string]]::new()
    $schedGuid = [guid]::Empty
    if (-not $scheduleId -or -not [guid]::TryParse($scheduleId, [ref]$schedGuid) -or $schedGuid -eq [guid]::Empty) {
        $reasons.Add('Missing or invalid eligibility schedule ID.')
    }
    if (-not $roleDefGuid) {
        $reasons.Add('Missing or invalid roleDefinitionId.')
    }
    if (-not $principalId) {
        $reasons.Add('Missing principalId.')
    }
    if ($status -ne 'Provisioned') {
        $reasons.Add("Eligibility status is '$status' instead of 'Provisioned'.")
    }
    $now = [DateTimeOffset]::UtcNow
    if ($startRaw) {
        $startParsed = [DateTimeOffset]::MinValue
        if ([DateTimeOffset]::TryParse($startRaw, [ref]$startParsed) -and $startParsed -gt $now) {
            $reasons.Add("Eligibility window has not started ($startRaw).")
        }
    }
    if ($endRaw) {
        $endParsed = [DateTimeOffset]::MinValue
        if ([DateTimeOffset]::TryParse($endRaw, [ref]$endParsed) -and $endParsed -le $now) {
            $reasons.Add("Eligibility window has expired ($endRaw).")
        }
    }

    return [pscustomobject]@{
        ScheduleId                     = if ($schedGuid -ne [guid]::Empty) { $schedGuid.ToString() } else { $scheduleId }
        EligibilityInstanceId          = Normalize-OptionalString ([string]$Item['name'])
        EligibilityScheduleResourceId  = Normalize-OptionalString ([string]($props['roleEligibilityScheduleId'] ?? $Item['id']))
        Scope                          = $normalizedScope
        ScopeDisplayName               = Normalize-OptionalString ([string]$expScope['displayName'])
        ScopeType                      = Normalize-OptionalString ([string]$expScope['type'])
        RoleDefinitionId               = $roleDefId
        RoleDefinitionGuid             = $roleDefGuid
        RoleName                       = Normalize-OptionalString ([string]$expRole['displayName'])
        PrincipalId                    = $principalId
        MemberType                     = Normalize-OptionalString ([string]$props['memberType'])
        Status                         = $status
        StartDateTime                  = $startRaw
        EndDateTime                    = $endRaw
        Condition                      = $condition
        ConditionVersion               = $conditionVersion
        HasCondition                   = [bool]$condition
        IsValid                        = ($reasons.Count -eq 0)
        ValidationReasons              = @($reasons)
    }
}

function Invoke-AzurePimEligibilityDiscovery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [string]$Scope = '/',
        [AllowNull()][string]$EligibleScope,
        [AllowNull()][string]$RoleName,
        [AllowNull()][string]$RoleDefinitionId,
        [AllowNull()][string]$ScheduleId,
        [AllowNull()][string]$PrincipalId,
        [switch]$Validate,
        [switch]$RequireSingle
    )
    $queryScope = Resolve-AzurePimScope -Scope $Scope
    $filterEligibleScope = if ($EligibleScope) { Resolve-AzurePimScope -Scope $EligibleScope } else { $null }
    $filterRoleGuid = if ($RoleDefinitionId) { Get-AzurePimRoleDefinitionGuid -RoleDefinitionId $RoleDefinitionId } else { $null }
    $filterRoleName = Normalize-OptionalString $RoleName
    $filterScheduleId = Normalize-OptionalString $ScheduleId
    if ($filterScheduleId) {
        $schedGuid = [guid]::Empty
        if (-not [guid]::TryParse($filterScheduleId, [ref]$schedGuid) -or $schedGuid -eq [guid]::Empty) {
            throw 'ScheduleId must be a nonempty GUID.'
        }
        $filterScheduleId = $schedGuid.ToString()
    }
    $filterPrincipal = Normalize-OptionalString $PrincipalId

    $uri = New-AzurePimArmUri -Scope $queryScope -ProviderPath 'roleEligibilityScheduleInstances' -QueryString '$filter=asTarget()&api-version=2020-10-01'
    $rawItems = Invoke-AzureResourcePimPagedGet -Context $Context -Uri $uri
    $results = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($rawItem in $rawItems) {
        $record = ConvertFrom-AzurePimEligibilityItem -Item $rawItem
        if ($filterEligibleScope -and $record.Scope -ine $filterEligibleScope) { continue }
        if ($filterRoleGuid -and $record.RoleDefinitionGuid -ine $filterRoleGuid) { continue }
        if ($filterRoleName -and $record.RoleName -ine $filterRoleName) { continue }
        if ($filterScheduleId -and $record.ScheduleId -ine $filterScheduleId) { continue }
        if ($filterPrincipal -and $record.PrincipalId -ine $filterPrincipal) { continue }
        $results.Add($record)
    }

    $matched = @($results)
    if ($Validate -or $RequireSingle) {
        if ($matched.Count -eq 0) {
            throw "No matching eligible Azure resource role assignment was found at query scope '$queryScope'."
        }
        if ($RequireSingle -and $matched.Count -gt 1) {
            throw "Multiple ($($matched.Count)) matching eligible Azure resource role assignments were found; specify -ScheduleId or -EligibleScope to disambiguate."
        }
        if ($Validate) {
            foreach ($entry in $matched) {
                if (-not $entry.IsValid) {
                    throw "Eligible role schedule '$($entry.ScheduleId)' failed validation: $($entry.ValidationReasons -join ' ')"
                }
            }
        }
    }
    return $matched
}

function Select-AzurePimEndUserPolicyRule {
    param(
        [Parameter(Mandatory)][object[]]$Rules,
        [Parameter(Mandatory)][string]$RuleType,
        [AllowNull()][string]$PreferredId
    )
    $ofType = @($Rules | Where-Object { $_ -is [System.Collections.IDictionary] -and $_['ruleType'] -eq $RuleType })
    if ($ofType.Count -eq 0) {
        return $null
    }
    if ($PreferredId) {
        $byId = @($ofType | Where-Object { $_['id'] -eq $PreferredId })
        if ($byId.Count -gt 0) {
            return $byId[0]
        }
    }
    $byTarget = @($ofType | Where-Object {
        $t = $_['target']
        $t -is [System.Collections.IDictionary] -and $t['caller'] -eq 'EndUser' -and $t['level'] -eq 'Assignment'
    })
    if ($byTarget.Count -gt 0) {
        return $byTarget[0]
    }
    $untargeted = @($ofType | Where-Object { -not $_['target'] })
    if ($untargeted.Count -gt 0) {
        return $untargeted[0]
    }
    return $null
}

function Get-AzurePimNestedDictionaryValue {
    param(
        [AllowNull()][object]$Root,
        [Parameter(Mandatory)][string[]]$Path
    )
    $current = $Root
    foreach ($segment in $Path) {
        if ($current -isnot [System.Collections.IDictionary] -or -not $current.Contains($segment)) {
            return $null
        }
        $current = $current[$segment]
    }
    return $current
}

function Resolve-AzurePimRoleGuidByNameAtScope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$RoleName
    )
    $escapedFilter = [uri]::EscapeDataString("roleName eq '$($RoleName.Replace("'", "''"))'")
    $uri = New-AzurePimArmUri -Scope $Scope -ProviderPath 'roleDefinitions' -QueryString "`$filter=$escapedFilter&api-version=2022-04-01"
    $defs = Invoke-AzureResourcePimPagedGet -Context $Context -Uri $uri
    $exact = @($defs | Where-Object {
        $p = $_['properties']
        $p -is [System.Collections.IDictionary] -and ([string]$p['roleName']).Equals($RoleName, [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($exact.Count -eq 0) {
        throw "Role definition '$RoleName' was not found at scope '$Scope'."
    }
    if ($exact.Count -gt 1) {
        throw "Multiple role definitions matched name '$RoleName' at scope '$Scope'; specify -RoleDefinitionId."
    }
    return Get-AzurePimRoleDefinitionGuid -RoleDefinitionId ([string]($exact[0]['id'] ?? $exact[0]['name']))
}

function Resolve-AzurePimActivationPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$Scope,
        [AllowNull()][string]$RoleName,
        [AllowNull()][string]$RoleDefinitionId,
        [switch]$RequireApproval
    )
    $exactScope = Resolve-AzurePimScope -Scope $Scope
    $targetRoleName = Normalize-OptionalString $RoleName
    $targetRoleGuid = if ($RoleDefinitionId) { Get-AzurePimRoleDefinitionGuid -RoleDefinitionId $RoleDefinitionId } else { $null }
    if (-not $targetRoleGuid -and -not $targetRoleName) {
        throw 'Specify -RoleDefinitionId or -RoleName when checking an effective Azure resource PIM policy.'
    }

    $assignmentsUri = New-AzurePimArmUri -Scope $exactScope -ProviderPath 'roleManagementPolicyAssignments' -QueryString 'api-version=2020-10-01'
    $assignments = Invoke-AzureResourcePimPagedGet -Context $Context -Uri $assignmentsUri

    if (-not $targetRoleGuid -and $targetRoleName) {
        $expandedMatch = @($assignments | Where-Object {
            $props = $_['properties']
            if ($props -isnot [System.Collections.IDictionary]) { return $false }
            $itemScope = Normalize-OptionalString ([string]$props['scope'])
            if ($itemScope -and (Resolve-AzurePimScope -Scope $itemScope) -ine $exactScope) { return $false }
            $expRole = Get-AzurePimNestedDictionaryValue -Root $props -Path @('expandedProperties', 'roleDefinition')
            $expRole -is [System.Collections.IDictionary] -and ([string]$expRole['displayName']).Equals($targetRoleName, [System.StringComparison]::OrdinalIgnoreCase)
        })
        if ($expandedMatch.Count -eq 1) {
            $targetRoleGuid = Get-AzurePimRoleDefinitionGuid -RoleDefinitionId ([string]$expandedMatch[0]['properties']['roleDefinitionId'])
        } else {
            $targetRoleGuid = Resolve-AzurePimRoleGuidByNameAtScope -Context $Context -Scope $exactScope -RoleName $targetRoleName
        }
    }

    # Strictly enforce exact requested scope: never accept a parent management-group policy assignment for a child scope.
    $matchingAssignments = @($assignments | Where-Object {
        $props = $_['properties']
        if ($props -isnot [System.Collections.IDictionary]) { return $false }
        $rawItemScope = Normalize-OptionalString ([string]$props['scope'])
        if (-not $rawItemScope) { return $false }
        if ((Resolve-AzurePimScope -Scope $rawItemScope) -ine $exactScope) { return $false }
        $itemRoleId = Normalize-OptionalString ([string]$props['roleDefinitionId'])
        if (-not $itemRoleId) { return $false }
        try {
            return ((Get-AzurePimRoleDefinitionGuid -RoleDefinitionId $itemRoleId) -ieq $targetRoleGuid)
        } catch {
            return $false
        }
    })

    if ($matchingAssignments.Count -eq 0) {
        throw "No effective role management policy assignment was found at exact scope '$exactScope' for role definition '$targetRoleGuid'."
    }
    if ($matchingAssignments.Count -gt 1) {
        throw "Multiple ($($matchingAssignments.Count)) role management policy assignments matched role definition '$targetRoleGuid' at scope '$exactScope'."
    }

    $assignment = $matchingAssignments[0]
    $assignmentProps = $assignment['properties']
    $rules = @()
    if ($assignmentProps.ContainsKey('effectiveRules') -and $null -ne $assignmentProps['effectiveRules']) {
        $rules = @($assignmentProps['effectiveRules'])
    } elseif ($assignmentProps.ContainsKey('policyAssignmentProperties') -and
              $assignmentProps['policyAssignmentProperties'] -is [System.Collections.IDictionary] -and
              $assignmentProps['policyAssignmentProperties']['policy'] -is [System.Collections.IDictionary] -and
              $assignmentProps['policyAssignmentProperties']['policy']['rules']) {
        $rules = @($assignmentProps['policyAssignmentProperties']['policy']['rules'])
    }

    $approvalRule = Select-AzurePimEndUserPolicyRule -Rules $rules -RuleType 'RoleManagementPolicyApprovalRule' -PreferredId 'Approval_EndUser_Assignment'
    $expirationRule = Select-AzurePimEndUserPolicyRule -Rules $rules -RuleType 'RoleManagementPolicyExpirationRule' -PreferredId 'Expiration_EndUser_Assignment'
    $enablementRule = Select-AzurePimEndUserPolicyRule -Rules $rules -RuleType 'RoleManagementPolicyEnablementRule' -PreferredId 'Enablement_EndUser_Assignment'
    $authCtxRule = Select-AzurePimEndUserPolicyRule -Rules $rules -RuleType 'RoleManagementPolicyAuthenticationContextRule' -PreferredId 'AuthenticationContext_EndUser_Assignment'

    $approvalSetting = if ($approvalRule -and $approvalRule['setting'] -is [System.Collections.IDictionary]) { $approvalRule['setting'] } else { @{} }
    $isApprovalRequired = [bool]($approvalSetting['isApprovalRequired'] -eq $true)
    $approvers = [System.Collections.Generic.List[string]]::new()
    if ($approvalSetting.ContainsKey('approvalStages') -and $null -ne $approvalSetting['approvalStages']) {
        foreach ($stage in @($approvalSetting['approvalStages'])) {
            if ($stage -is [System.Collections.IDictionary] -and $stage['primaryApprovers']) {
                foreach ($approver in @($stage['primaryApprovers'])) {
                    if ($approver -is [System.Collections.IDictionary]) {
                        $label = Normalize-OptionalString ([string]($approver['displayName'] ?? $approver['id'] ?? $approver['objectId']))
                        if ($label) { $approvers.Add($label) }
                    }
                }
            }
        }
    }

    [string[]]$enabledRules = if ($enablementRule -and $enablementRule['enabledRules']) { @($enablementRule['enabledRules'] | ForEach-Object { [string]$_ }) } else { @() }
    [string[]]$primaryApprovers = $approvers.ToArray()
    $resolvedRoleName = Normalize-OptionalString ([string]((Get-AzurePimNestedDictionaryValue -Root $assignmentProps -Path @('expandedProperties', 'roleDefinition', 'displayName')) ?? $targetRoleName))
    $maxDuration = if ($expirationRule) { Normalize-OptionalString ([string]$expirationRule['maximumDuration']) } else { $null }
    $isAuthCtxRequired = [bool]($authCtxRule -and $authCtxRule['isEnabled'] -eq $true)
    $authCtxClaimValue = if ($authCtxRule) { Normalize-OptionalString ([string]$authCtxRule['claimValue']) } else { $null }

    $policySummary = [pscustomobject]@{
        Scope                          = $exactScope
        PolicyAssignmentId             = Normalize-OptionalString ([string]($assignment['id'] ?? $assignment['name']))
        PolicyId                       = Normalize-OptionalString ([string]$assignmentProps['policyId'])
        RoleDefinitionId               = Normalize-OptionalString ([string]$assignmentProps['roleDefinitionId'])
        RoleDefinitionGuid             = $targetRoleGuid
        RoleName                       = $resolvedRoleName
        ApprovalRulePresent            = [bool]($null -ne $approvalRule)
        IsApprovalRequired             = $isApprovalRequired
        ApprovalMode                   = Normalize-OptionalString ([string]$approvalSetting['approvalMode'])
        PrimaryApproverCount           = $primaryApprovers.Count
        PrimaryApprovers               = $primaryApprovers
        IsRequestorJustificationRequired = [bool]($approvalSetting['isRequestorJustificationRequired'] -eq $true)
        IsExpirationRequired           = [bool]($expirationRule -and $expirationRule['isExpirationRequired'] -eq $true)
        MaximumDuration                = $maxDuration
        EnabledRules                   = $enabledRules
        IsJustificationRequired        = ('Justification' -in $enabledRules) -or [bool]($approvalSetting['isRequestorJustificationRequired'] -eq $true)
        IsMfaRequired                  = ('MultiFactorAuthentication' -in $enabledRules)
        IsTicketingRequired            = ('Ticketing' -in $enabledRules)
        IsAuthenticationContextRequired = $isAuthCtxRequired
        AuthenticationContextClaimValue = $authCtxClaimValue
        ClaimsChallengeSatisfied       = [bool]$Context.ClaimsChallengeSatisfied
    }

    if ($RequireApproval -and -not $policySummary.IsApprovalRequired) {
        $roleDisplay = if ($resolvedRoleName) { $resolvedRoleName } else { $targetRoleGuid }
        throw "Effective PIM policy at exact scope '$exactScope' for role '$roleDisplay' does not require approval (IsApprovalRequired=$($policySummary.IsApprovalRequired))."
    }

    return $policySummary
}

function ConvertFrom-AzurePimAssignmentInstanceItem {
    param([Parameter(Mandatory)][hashtable]$Item)
    $props = if ($Item.ContainsKey('properties') -and $Item['properties'] -is [System.Collections.IDictionary]) { $Item['properties'] } else { @{} }
    $expanded = if ($props.ContainsKey('expandedProperties') -and $props['expandedProperties'] -is [System.Collections.IDictionary]) { $props['expandedProperties'] } else { @{} }
    $rawScope = Normalize-OptionalString ([string]($props['scope'] ?? (Get-AzurePimNestedDictionaryValue -Root $expanded -Path @('scope', 'id'))))
    $normalizedScope = if ($rawScope) { Resolve-AzurePimScope -Scope $rawScope } else { $null }
    $roleDefId = Normalize-OptionalString ([string]($props['roleDefinitionId'] ?? (Get-AzurePimNestedDictionaryValue -Root $expanded -Path @('roleDefinition', 'id'))))
    $roleDefGuid = if ($roleDefId) {
        try { Get-AzurePimRoleDefinitionGuid -RoleDefinitionId $roleDefId } catch { $null }
    } else {
        $null
    }
    return [pscustomobject]@{
        RoleAssignmentScheduleInstanceId = Normalize-OptionalString ([string]$Item['name'])
        RoleAssignmentScheduleId         = Normalize-OptionalString ([string]$props['roleAssignmentScheduleId'])
        Scope                            = $normalizedScope
        RoleDefinitionId                 = $roleDefId
        RoleDefinitionGuid               = $roleDefGuid
        RoleName                         = Normalize-OptionalString ([string](Get-AzurePimNestedDictionaryValue -Root $expanded -Path @('roleDefinition', 'displayName')))
        PrincipalId                      = Normalize-OptionalString ([string]($props['principalId'] ?? (Get-AzurePimNestedDictionaryValue -Root $expanded -Path @('principal', 'id'))))
        AssignmentType                   = Normalize-OptionalString ([string]$props['assignmentType'])
        MemberType                       = Normalize-OptionalString ([string]$props['memberType'])
        Status                           = Normalize-OptionalString ([string]$props['status'])
        StartDateTime                    = ConvertFrom-AzurePimTimestamp $props['startDateTime']
        EndDateTime                      = ConvertFrom-AzurePimTimestamp $props['endDateTime']
        Condition                        = Normalize-OptionalString ([string]$props['condition'])
        ConditionVersion                 = Normalize-OptionalString ([string]$props['conditionVersion'])
    }
}

function ConvertFrom-AzurePimRequestItem {
    param(
        [Parameter(Mandatory)][hashtable]$Item,
        [AllowEmptyCollection()][pscustomobject[]]$ActiveInstances = @()
    )
    $props = if ($Item.ContainsKey('properties') -and $Item['properties'] -is [System.Collections.IDictionary]) { $Item['properties'] } else { @{} }
    $expanded = if ($props.ContainsKey('expandedProperties') -and $props['expandedProperties'] -is [System.Collections.IDictionary]) { $props['expandedProperties'] } else { @{} }
    $schedInfo = if ($props.ContainsKey('scheduleInfo') -and $props['scheduleInfo'] -is [System.Collections.IDictionary]) { $props['scheduleInfo'] } else { @{} }
    $expiration = if ($schedInfo.ContainsKey('expiration') -and $schedInfo['expiration'] -is [System.Collections.IDictionary]) { $schedInfo['expiration'] } else { @{} }

    $rawScope = Normalize-OptionalString ([string]($props['scope'] ?? (Get-AzurePimNestedDictionaryValue -Root $expanded -Path @('scope', 'id'))))
    $normalizedScope = if ($rawScope) { Resolve-AzurePimScope -Scope $rawScope } else { $null }
    $roleDefId = Normalize-OptionalString ([string]($props['roleDefinitionId'] ?? (Get-AzurePimNestedDictionaryValue -Root $expanded -Path @('roleDefinition', 'id'))))
    $roleDefGuid = if ($roleDefId) {
        try { Get-AzurePimRoleDefinitionGuid -RoleDefinitionId $roleDefId } catch { $null }
    } else {
        $null
    }
    $principalId = Normalize-OptionalString ([string]($props['principalId'] ?? (Get-AzurePimNestedDictionaryValue -Root $expanded -Path @('principal', 'id'))))
    $targetSchedId = Normalize-OptionalString ([string]$props['targetRoleAssignmentScheduleId'])
    $targetInstId = Normalize-OptionalString ([string]$props['targetRoleAssignmentScheduleInstanceId'])
    $requestCondition = Normalize-OptionalString ([string]$props['condition'])

    $matchedActive = $null
    if ($ActiveInstances.Count -gt 0) {
        if ($targetInstId) {
            $matchedActive = $ActiveInstances | Where-Object {
                $_.RoleAssignmentScheduleInstanceId -ieq $targetInstId -or
                ($_.RoleAssignmentScheduleInstanceId -and ($targetInstId -split '/')[-1] -ieq $_.RoleAssignmentScheduleInstanceId)
            } | Select-Object -First 1
        }
        if (-not $matchedActive -and $targetSchedId) {
            $targetSchedLeaf = ($targetSchedId -split '/')[-1]
            $matchedActive = $ActiveInstances | Where-Object {
                $instSched = Normalize-OptionalString $_.RoleAssignmentScheduleId
                $instSched -and (($instSched -ieq $targetSchedId) -or (($instSched -split '/')[-1] -ieq $targetSchedLeaf))
            } | Select-Object -First 1
        }
        if (-not $matchedActive -and [string]$props['status'] -eq 'Provisioned' -and $roleDefGuid -and $principalId) {
            $matchedActive = $ActiveInstances | Where-Object {
                $_.PrincipalId -ieq $principalId -and
                $_.RoleDefinitionGuid -ieq $roleDefGuid -and
                (-not $normalizedScope -or $_.Scope -ieq $normalizedScope) -and
                ($_.AssignmentType -eq 'Activated' -or -not $_.AssignmentType) -and
                (-not $requestCondition -or $_.Condition -ceq $requestCondition)
            } | Select-Object -First 1
        }
    }

    $isActive = $false
    if ($null -ne $matchedActive -and $matchedActive.Status -eq 'Provisioned') {
        $now = [DateTimeOffset]::UtcNow
        $started = $true
        $notExpired = $true
        if ($matchedActive.StartDateTime) {
            $s = [DateTimeOffset]::MinValue
            if ([DateTimeOffset]::TryParse($matchedActive.StartDateTime, [ref]$s)) { $started = ($s -le $now) }
        }
        if ($matchedActive.EndDateTime) {
            $e = [DateTimeOffset]::MinValue
            if ([DateTimeOffset]::TryParse($matchedActive.EndDateTime, [ref]$e)) { $notExpired = ($e -gt $now) }
        }
        $isActive = $started -and $notExpired
    }

    return [pscustomobject]@{
        RequestId                            = Normalize-OptionalString ([string]$Item['name'])
        RequestResourceId                    = Normalize-OptionalString ([string]$Item['id'])
        ApprovalId                           = Normalize-OptionalString ([string]$props['approvalId'])
        RequestType                          = Normalize-OptionalString ([string]$props['requestType'])
        Status                               = Normalize-OptionalString ([string]$props['status'])
        Scope                                = $normalizedScope
        RoleDefinitionId                     = $roleDefId
        RoleDefinitionGuid                   = $roleDefGuid
        RoleName                             = Normalize-OptionalString ([string](Get-AzurePimNestedDictionaryValue -Root $expanded -Path @('roleDefinition', 'displayName')))
        PrincipalId                          = $principalId
        LinkedRoleEligibilityScheduleId      = Normalize-OptionalString ([string]$props['linkedRoleEligibilityScheduleId'])
        Duration                             = Normalize-OptionalString ([string]$expiration['duration'])
        StartDateTime                        = ConvertFrom-AzurePimTimestamp $schedInfo['startDateTime']
        Justification                        = Normalize-OptionalString ([string]$props['justification'])
        Condition                            = $requestCondition
        ConditionVersion                     = Normalize-OptionalString ([string]$props['conditionVersion'])
        TargetRoleAssignmentScheduleId       = $targetSchedId
        TargetRoleAssignmentScheduleInstanceId = $targetInstId
        CreatedOn                            = ConvertFrom-AzurePimTimestamp $props['createdOn']
        IsActive                             = $isActive
        ActiveAssignment                     = $matchedActive
    }
}
