# TAP-cookie utility uses the same bounded, state-bound authentication as registration.
function Invoke-EntraEstsCookieViaTapUtility {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Security.SecureString]$TAP,
        [Parameter(Mandatory)][ValidatePattern('^[^\s@]+@[^\s@]+$')][string]$UserPrincipalName,
        [string]$TenantId,
        [ValidateSet('SecurityInfoBootstrap')][string]$Purpose = 'SecurityInfoBootstrap',
        [switch]$AsPlainText
    )
    if ($TAP.Length -eq 0) { throw 'A nonempty secure TAP is required.' }
    if ($TenantId) { $null = Resolve-EntraRegistrationTenant -TenantId $TenantId -UserPrincipalName $UserPrincipalName }
    $context = $null
    try {
        $context = New-EntraRegistrationContext
        $null = Invoke-EntraRegistrationTapAuthentication -Context $context -TAP $TAP `
            -UserPrincipalName $UserPrincipalName -TenantId $TenantId
        # Authentication has already checked the OAuth state and the client, tenant and user binding.
        $cookies = @($context.WebSession.Cookies.GetCookies([uri]'https://login.microsoftonline.com/') |
            Where-Object { $_.Name -cin @('ESTSAUTH', 'ESTSAUTHPERSISTENT') -and -not $_.Expired -and $_.Value })
        $selected = @($cookies | Where-Object { $_.Name -ceq 'ESTSAUTH' })
        if ($selected.Count -eq 0) { $selected = @($cookies | Where-Object { $_.Name -ceq 'ESTSAUTHPERSISTENT' }) }
        if ($selected.Count -ne 1) { throw 'An unambiguous ESTS authentication cookie was not returned.' }
        $cookie = $selected[0]
        if ($cookie.Value -match '[\r\n;]') { throw 'The returned ESTS cookie value is invalid.' }
        if ($AsPlainText) { return [string]$cookie.Value }
        return [pscustomobject]@{
            CookieName = [string]$cookie.Name
            CookieValue = ConvertTo-SecureString -String $cookie.Value -AsPlainText -Force
            TenantId = $context.TenantId
            UserPrincipalName = $UserPrincipalName
            Purpose = $Purpose
        }
    } finally {
        Clear-EntraRegistrationContext -Context $context
        $cookies = $null; $selected = $null; $cookie = $null
    }
}
