function Get-EntraKeyVaultProvisioningErrorMessage {
    param($Content)
    if (-not $Content) { return 'Unknown error' }
    try { $value = if ($Content -is [string]) { $Content | ConvertFrom-Json -ErrorAction Stop } else { $Content } }
    catch { return 'Azure returned a non-JSON error response.' }
    $errorBody = if ($value.error) { $value.error } else { $value }
    if ($errorBody.code -and $errorBody.message) { return "$($errorBody.code): $($errorBody.message)" }
    if ($errorBody.message) { return [string]$errorBody.message }
    return 'Azure returned an unspecified error.'
}

function Test-EntraKeyVaultProvisioningNotFound {
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    if ($ErrorRecord.Exception.Response -and [int]$ErrorRecord.Exception.Response.StatusCode -eq 404) { return $true }
    ($ErrorRecord.Exception.Message + ' ' + $ErrorRecord.ErrorDetails.Message) -match '(^|\D)404(\D|$)|ResourceNotFound|was not found'
}

function Invoke-EntraKeyVaultProvisioningArmRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PUT', 'PATCH')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [string]$Payload,
        [ValidateRange(1, 10)][int]$MaxRetries = 3,
        [ValidateRange(0, 60)][int]$RetryDelaySeconds = 2
    )
    $parsed = [uri]$Uri
    if ($parsed.Scheme -ne 'https' -or $parsed.Host -ne 'management.azure.com' -or $parsed.Port -ne 443 -or $parsed.UserInfo) {
        throw 'Refusing untrusted Azure management endpoint.'
    }
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $parameters = @{ Method = $Method; Uri = $Uri; ErrorAction = 'Stop'; Verbose = $false; Debug = $false }
            if ($Payload) { $parameters.Payload = $Payload }
            $response = Invoke-AzRestMethod @parameters
            if ([int]$response.StatusCode -ge 200 -and [int]$response.StatusCode -lt 300) { return $response }
            $message = Get-EntraKeyVaultProvisioningErrorMessage -Content $response.Content
            throw "HTTP $($response.StatusCode): $message"
        } catch {
            $transient = $_.Exception.Message -match '^HTTP (429|500|502|503|504):|temporarily unavailable|timed out|timeout|connection.*closed|transport connection'
            if (-not $transient -or $attempt -eq $MaxRetries) { throw }
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}

function Get-EntraKeyVaultProvisioningContext {
    [CmdletBinding()]
    param([string]$SubscriptionId, [switch]$SkipKeyVault)
    $graph = Get-MgContext -Verbose:$false -Debug:$false -ErrorAction Stop
    if (-not $graph -or -not $graph.TenantId) {
        Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All' -NoWelcome -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null
        $graph = Get-MgContext -Verbose:$false -Debug:$false -ErrorAction Stop
    }
    if (-not $graph.TenantId) { throw 'Microsoft Graph connection did not establish a tenant context.' }
    $azure = $null
    if (-not $SkipKeyVault) {
        $azure = Get-AzContext -Verbose:$false -Debug:$false -ErrorAction Stop
        if (-not $azure -or -not $azure.Account) {
            Connect-AzAccount -WarningAction SilentlyContinue -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null
            $azure = Get-AzContext -Verbose:$false -Debug:$false -ErrorAction Stop
        }
        if (-not $azure.Account) { throw 'Azure connection did not establish an account context.' }
        if ($azure.Tenant.Id -ne $graph.TenantId) {
            Set-AzContext -Tenant $graph.TenantId -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null
            $azure = Get-AzContext -Verbose:$false -Debug:$false -ErrorAction Stop
        }
        if ($SubscriptionId -and $azure.Subscription.Id -ne $SubscriptionId) {
            Set-AzContext -SubscriptionId $SubscriptionId -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null
            $azure = Get-AzContext -Verbose:$false -Debug:$false -ErrorAction Stop
        }
        if ($azure.Tenant.Id -ne $graph.TenantId -or ($SubscriptionId -and $azure.Subscription.Id -ne $SubscriptionId)) {
            throw 'Azure context does not match the requested subscription and Microsoft Graph tenant.'
        }
        $SubscriptionId = [string]$azure.Subscription.Id
        if (-not $SubscriptionId) { throw 'Azure context has no subscription.' }
    }
    [pscustomobject]@{
        TenantId = [string]$graph.TenantId; SubscriptionId = $SubscriptionId
        CanGrantConsent = $graph.Scopes -contains 'AppRoleAssignment.ReadWrite.All'
    }
}
