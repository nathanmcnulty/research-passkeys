function New-EntraKeyVaultProvisioningSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ApplicationObjectId,
        [Parameter(Mandatory)][string]$ApplicationId,
        [Parameter(Mandatory)][string]$TenantId,
        [ValidateRange(1, 24)][int]$ExpirationMonths = 12,
        [switch]$SkipKeyVault
    )
    $expiration = (Get-Date).ToUniversalTime().AddMonths($ExpirationMonths).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $body = @{ passwordCredential = @{ displayName = 'Created by Initialize-EntraPasskeyKeyVault'; endDateTime = $expiration } } | ConvertTo-Json
    $secret = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$ApplicationObjectId/addPassword" -Body $body -Verbose:$false -Debug:$false -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace([string]$secret.secretText) -or $secret.secretText -match '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$') {
        throw 'Microsoft Graph did not return the new client secret value.'
    }
    foreach ($scope in @('https://graph.microsoft.com/.default', $(if (-not $SkipKeyVault) { 'https://vault.azure.net/.default' }))) {
        if (-not $scope) { continue }
        $ready = $false
        for ($attempt = 1; $attempt -le 12; $attempt++) {
            Start-Sleep -Seconds 5
            try {
                $token = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST `
                    -Body @{ grant_type = 'client_credentials'; client_id = $ApplicationId; client_secret = $secret.secretText; scope = $scope } `
                    -ContentType 'application/x-www-form-urlencoded' -MaximumRedirection 0 -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 60 -Verbose:$false -Debug:$false -ErrorAction Stop
                if ($token.access_token) { $ready = $true; break }
            } catch { Write-Verbose 'Waiting for the new client credential to replicate.' }
        }
        if (-not $ready) { Write-Warning 'New client credential token acquisition could not be confirmed; allow time for replication.' }
    }
    [pscustomobject]@{ ClientSecret = [string]$secret.secretText; SecretExpiration = $expiration }
}
