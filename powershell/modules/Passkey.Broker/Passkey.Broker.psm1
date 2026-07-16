$script:PasskeyBrokerContext = $null

function ConvertFrom-PasskeySecureString {
    param([Parameter(Mandatory)][System.Security.SecureString]$SecureString)
    $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Resolve-PasskeyBrokerUri {
    param([Parameter(Mandatory)][string]$Uri)
    $candidate = $Uri.Trim().TrimEnd('/')
    try { $parsed = [uri]$candidate } catch { throw [System.ArgumentException]::new("Invalid broker URI '$Uri'.") }
    if (-not $parsed.IsAbsoluteUri -or $parsed.Scheme -notin @('https', 'http')) {
        throw [System.ArgumentException]::new('Broker URI must be an absolute HTTP or HTTPS URI.')
    }
    if ($parsed.Scheme -eq 'http' -and $parsed.Host -notin @('localhost', '127.0.0.1', '::1')) {
        throw [System.ArgumentException]::new('Broker URI must use HTTPS except for localhost development.')
    }
    if ($parsed.Query -or $parsed.Fragment) {
        throw [System.ArgumentException]::new('Broker URI must not include a query string or fragment.')
    }
    if ($candidate.EndsWith('/api', [System.StringComparison]::OrdinalIgnoreCase)) {
        $candidate = $candidate.Substring(0, $candidate.Length - 4)
    }
    return $candidate.TrimEnd('/')
}

function Assert-PasskeyBrokerConnected {
    if (-not $script:PasskeyBrokerContext -or -not $script:PasskeyBrokerContext.FunctionKey) {
        throw [System.InvalidOperationException]::new('Not connected to a passkey broker. Run Connect-PasskeyBroker first.')
    }
}

function Invoke-PasskeyBrokerRequest {
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST')][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [Parameter()]$Body
    )
    Assert-PasskeyBrokerConnected
    $plainKey = ConvertFrom-PasskeySecureString -SecureString $script:PasskeyBrokerContext.FunctionKey
    try {
        $parameters = @{
            Method = $Method
            Uri = "$($script:PasskeyBrokerContext.Uri)/api/$($Path.TrimStart('/'))"
            Headers = @{ 'x-functions-key' = $plainKey }
            ErrorAction = 'Stop'
        }
        if ($PSBoundParameters.ContainsKey('Body')) {
            $parameters.ContentType = 'application/json'
            $parameters.Body = $Body | ConvertTo-Json -Depth 10 -Compress
        }
        return Invoke-RestMethod @parameters
    } finally {
        $plainKey = $null
    }
}

function Get-PasskeyProfileConfiguration {
    param([Parameter(Mandatory)][string]$Profile)
    Assert-PasskeyBrokerConnected
    return @($script:PasskeyBrokerContext.Configuration.profiles) |
        Where-Object { [string]::Equals([string]$_.name, $Profile, [System.StringComparison]::OrdinalIgnoreCase) } |
        Select-Object -First 1
}

function Connect-PasskeyBroker {
    <#
    .SYNOPSIS
        Connects the current PowerShell process to a passkey broker Function App.
    .PARAMETER Uri
        Function App base URI. A trailing /api is accepted and normalized.
    .PARAMETER FunctionKey
        Azure Functions host or function key, retained as a SecureString in module scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][System.Security.SecureString]$FunctionKey
    )
    $normalizedUri = Resolve-PasskeyBrokerUri -Uri $Uri
    $previous = $script:PasskeyBrokerContext
    $script:PasskeyBrokerContext = [pscustomobject]@{
        Uri = $normalizedUri
        FunctionKey = $FunctionKey.Copy()
        Configuration = $null
        ConnectedAt = [datetimeoffset]::UtcNow
    }
    try {
    $configuration = Invoke-PasskeyBrokerRequest -Method GET -Path 'broker/config'
        if (-not $configuration.success -or -not $configuration.tenantId) {
            throw [System.InvalidOperationException]::new('The endpoint did not return a valid passkey broker configuration.')
        }
        $script:PasskeyBrokerContext.Configuration = $configuration
        if ($previous -and $previous.FunctionKey) { $previous.FunctionKey.Dispose() }
    } catch {
        Disconnect-PasskeyBroker
        $script:PasskeyBrokerContext = $previous
        throw
    }
    return Get-PasskeyBrokerContext
}

function Get-PasskeyBrokerContext {
    <# .SYNOPSIS Returns the current broker connection without credentials. #>
    [CmdletBinding()]
    param()
    if (-not $script:PasskeyBrokerContext) {
        return [pscustomobject]@{ Connected = $false; Uri = $null; TenantId = $null; TokenClientId = $null; Profiles = @(); ConnectedAt = $null }
    }
    return [pscustomobject]@{
        Connected = [bool]$script:PasskeyBrokerContext.Configuration
        Uri = $script:PasskeyBrokerContext.Uri
        TenantId = $script:PasskeyBrokerContext.Configuration.tenantId
        TokenClientId = $script:PasskeyBrokerContext.Configuration.tokenClientId
        TokenRedirectUri = $script:PasskeyBrokerContext.Configuration.tokenRedirectUri
        Profiles = @($script:PasskeyBrokerContext.Configuration.profiles)
        ConnectedAt = $script:PasskeyBrokerContext.ConnectedAt
    }
}

function Get-PasskeyRecord {
    <#
    .SYNOPSIS Gets one canonical passkey record from the connected broker.
    .PARAMETER RecordId The canonical passkey record ID.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RecordId)
    $response = Invoke-PasskeyBrokerRequest -Method GET -Path "passkeys/$([uri]::EscapeDataString($RecordId))"
    if (-not $response.success -or -not $response.record) { throw 'The broker did not return a passkey record.' }
    return $response.record
}

function Get-PasskeyAccessToken {
    <#
    .SYNOPSIS Acquires a fresh delegated access token using a stored Entra passkey.
    .PARAMETER RecordId The canonical Entra passkey record ID.
    .PARAMETER Profile MicrosoftGraph or AzureResourceManager.
    .PARAMETER Scopes Optional Graph scope subset. Graph defaults to User.Read; ARM is fixed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RecordId,
        [Parameter(Mandatory)][ValidateSet('MicrosoftGraph', 'AzureResourceManager')][string]$Profile,
        [Parameter()][string[]]$Scopes
    )
    $profileConfiguration = Get-PasskeyProfileConfiguration -Profile $Profile
    if (-not $profileConfiguration) { throw [System.ArgumentException]::new("Profile '$Profile' is not configured by this broker.") }
    $requestedScopes = if ($PSBoundParameters.ContainsKey('Scopes') -and $Scopes.Count -gt 0) { @($Scopes) } else { @($profileConfiguration.defaultScopes) }
    $allowedScopes = @($profileConfiguration.allowedScopes)
    foreach ($scope in $requestedScopes) {
        if (-not ($allowedScopes | Where-Object { [string]::Equals([string]$_, [string]$scope, [System.StringComparison]::OrdinalIgnoreCase) })) {
            throw [System.ArgumentException]::new("Scope '$scope' is not allowed for profile '$Profile'.")
        }
    }
    $response = Invoke-PasskeyBrokerRequest -Method POST -Path "entra/passkeys/$([uri]::EscapeDataString($RecordId))/token" -Body @{
        profile = $Profile
        scopes = $requestedScopes
    }
    if (-not $response.success -or [string]::IsNullOrWhiteSpace([string]$response.accessToken)) {
        throw 'The broker did not return an access token.'
    }
    $result = [pscustomobject]@{
        TokenType = [string]$response.tokenType
        AccessToken = ConvertTo-SecureString -String ([string]$response.accessToken) -AsPlainText -Force
        ExpiresOn = [datetimeoffset]::Parse([string]$response.expiresOn)
        TenantId = [string]$response.tenantId
        AccountId = [string]$response.accountId
        Profile = [string]$response.profile
        Scopes = @($response.scopes)
    }
    $response.accessToken = $null
    return $result
}

function Connect-MgGraphWithPasskey {
    <#
    .SYNOPSIS Connects Microsoft Graph PowerShell with a fresh passkey-acquired token.
    .PARAMETER RecordId The canonical Entra passkey record ID.
    .PARAMETER Scopes Graph delegated scopes; defaults to User.Read.
    .PARAMETER PassThru Returns Get-MgContext after connecting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RecordId,
        [Parameter()][string[]]$Scopes,
        [Parameter()][switch]$PassThru
    )
    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
        throw [System.Management.Automation.CommandNotFoundException]::new('Microsoft.Graph.Authentication is required. Install and import it before using Connect-MgGraphWithPasskey.')
    }
    $tokenParameters = @{ RecordId = $RecordId; Profile = 'MicrosoftGraph' }
    if ($PSBoundParameters.ContainsKey('Scopes')) { $tokenParameters.Scopes = $Scopes }
    $token = Get-PasskeyAccessToken @tokenParameters
    Connect-MgGraph -AccessToken $token.AccessToken -NoWelcome | Out-Null
    if ($PassThru) { return Get-MgContext }
}

function Connect-AzAccountWithPasskey {
    <#
    .SYNOPSIS Connects Az PowerShell with a fresh passkey-acquired ARM token.
    .PARAMETER RecordId The canonical Entra passkey record ID.
    .PARAMETER SubscriptionId Optional Azure subscription ID or name.
    .PARAMETER PassThru Returns Get-AzContext after connecting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RecordId,
        [Parameter()][string]$SubscriptionId,
        [Parameter()][switch]$PassThru
    )
    if (-not (Get-Command Connect-AzAccount -ErrorAction SilentlyContinue)) {
        throw [System.Management.Automation.CommandNotFoundException]::new('Az.Accounts is required. Install and import it before using Connect-AzAccountWithPasskey.')
    }
    $token = Get-PasskeyAccessToken -RecordId $RecordId -Profile AzureResourceManager
    $plainToken = ConvertFrom-PasskeySecureString -SecureString $token.AccessToken
    try {
        $parameters = @{ AccessToken = $plainToken; AccountId = $token.AccountId; Tenant = $token.TenantId }
        if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) { $parameters.Subscription = $SubscriptionId }
        Connect-AzAccount @parameters | Out-Null
    } finally {
        $plainToken = $null
    }
    if ($PassThru) { return Get-AzContext }
}

function Disconnect-PasskeyBroker {
    <# .SYNOPSIS Clears the current process-local passkey broker connection. #>
    [CmdletBinding()]
    param()
    if ($script:PasskeyBrokerContext -and $script:PasskeyBrokerContext.FunctionKey) {
        $script:PasskeyBrokerContext.FunctionKey.Dispose()
    }
    $script:PasskeyBrokerContext = $null
}

Export-ModuleMember -Function Connect-PasskeyBroker, Get-PasskeyBrokerContext, Get-PasskeyRecord, Get-PasskeyAccessToken, Connect-MgGraphWithPasskey, Connect-AzAccountWithPasskey, Disconnect-PasskeyBroker
