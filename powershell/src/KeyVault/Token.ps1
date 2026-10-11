function Get-KeyVaultToken {
    [CmdletBinding()]
    param([string]$AccessToken, [string]$TenantId, [string]$ClientId, [string]$ClientSecret)
    if (-not [string]::IsNullOrWhiteSpace($AccessToken)) { return $AccessToken }
    $tenantGuid=[guid]::Empty
    if ($TenantId -and (-not [guid]::TryParse($TenantId,[ref]$tenantGuid) -or $tenantGuid -eq [guid]::Empty)) {
        throw 'Key Vault tenant ID must be a GUID.'
    }
    if (Get-Command Get-AzAccessToken -ErrorAction SilentlyContinue) {
        try {
            $args = @{ ResourceUrl='https://vault.azure.net'; ErrorAction='Stop'; Verbose=$false; Debug=$false }
            if ($TenantId) { $args.TenantId = $TenantId }
            $azToken = Get-AzAccessToken @args
            $token = ConvertTo-PlainTextValue $azToken.Token
            if (-not [string]::IsNullOrWhiteSpace($token)) { return $token }
        } catch { Write-Verbose 'Az token acquisition failed; details suppressed.' }
    }
    $cli = Get-Command az -CommandType Application -ErrorAction SilentlyContinue
    if ($cli) {
        try {
            $args = @('account','get-access-token','--resource','https://vault.azure.net','--output','json')
            if ($TenantId) { $args += @('--tenant',$TenantId) }
            $response = Invoke-PasskeyExternalCommand -FilePath $cli.Source -Arguments $args
            if ($response.ExitCode -eq 0) {
                $token = ($response.Output | ConvertFrom-Json -ErrorAction Stop).accessToken
                if ($token -is [string] -and -not [string]::IsNullOrWhiteSpace($token)) { return $token }
            }
        } catch { Write-Verbose 'CLI token acquisition failed; details suppressed.' }
    }
    if ($ClientId -and $ClientSecret -and $TenantId) {
        $client = [guid]::Empty
        if (-not [guid]::TryParse($ClientId,[ref]$client) -or $client -eq [guid]::Empty) { throw 'Key Vault client ID must be a GUID.' }
        try {
            $body = @{ grant_type='client_credentials';client_id=$ClientId;client_secret=$ClientSecret;scope='https://vault.azure.net/.default' }
            $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' -MaximumRedirection 0 -ConnectionTimeoutSeconds 30 -OperationTimeoutSeconds 30 -Verbose:$false -Debug:$false -ErrorAction Stop
            if ($response.access_token -isnot [string] -or [string]::IsNullOrWhiteSpace($response.access_token)) { throw 'Empty token.' }
            return $response.access_token
        } catch { throw 'Key Vault service-principal token acquisition failed; details suppressed.' }
    }
    throw 'Provide -KeyVaultAccessToken, an authenticated Az/CLI session, or Key Vault client/tenant credentials.'
}
