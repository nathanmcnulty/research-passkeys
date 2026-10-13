function Complete-EntraPasskeyLogin {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context,[switch]$IncludeAuthenticationCookie,[switch]$IncludeAuthenticationSession)
    $cookie=Select-PreferredEstsCookie @(Get-AllCookiesFromContainer $Context.Session.Cookies)
    if (-not $cookie) {
        foreach ($attempt in 1..3) {
            $response=Invoke-EntraLoginWebRequest -Context $Context -Uri $Context.AuthUrl
            $state=Read-EntraLoginPage -Response $response
            if ($state.pgid) { throw 'Entra login has a pending interaction; authentication is not complete.' }
            $cookie=Select-PreferredEstsCookie @(Get-AllCookiesFromContainer $Context.Session.Cookies)
            if ($cookie) { break }
        }
    }
    $result=[pscustomobject]@{
        UserPrincipalName=$Context.UserPrincipalName;AuthenticationMethod='Legacy software FIDO2 assertion'
        SignatureMethod=if ($Context.KeyVaultInfo) {'Azure Key Vault'} else {'Local Private Key'}
        KeyVaultName=if ($Context.KeyVaultInfo) {$Context.KeyVaultInfo.vaultName} else {$null}
        CookieType=if ($cookie) {$cookie.Name} else {$null}
        AuthenticationCookieName=if ($cookie) {$cookie.Name} else {$null}
        AuthenticationCookieValue=if ($cookie -and $IncludeAuthenticationCookie) {$cookie.Value} else {$null}
        TokenVariable=$null;SessionVariable=$null;SessionPersistedToGlobalScope=$false
        AuthenticationTime=Get-Date;Success=[bool]$cookie
        LegacySoftwareAssertion=$true;UserPresenceVerified=$false;UserVerificationVerified=$false
    }
    if ($IncludeAuthenticationSession) { $result | Add-Member -NotePropertyName AuthenticationSession -NotePropertyValue $Context.Session }
    return $result
}
