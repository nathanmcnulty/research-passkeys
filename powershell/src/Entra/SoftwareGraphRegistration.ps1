function Get-EntraSoftwareGraphCreationOptions {
    param([Parameter(Mandatory)][string]$UserUpn, [Parameter(Mandatory)][string]$AccessToken)
    $user = [uri]::EscapeDataString($UserUpn)
    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/users/$user/authentication/fido2Methods/creationOptions(challengeTimeoutInMinutes=10)" `
        -Headers @{ Authorization = "Bearer $AccessToken" } -MaximumRedirection 0 -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 60 -Verbose:$false -Debug:$false -ErrorAction Stop
    if ($response.publicKey.rp.id -cne 'login.microsoft.com' -or $response.publicKey.user.name -ine $UserUpn) {
        throw 'Graph creation options did not bind the requested user and relying party.'
    }
    foreach ($value in @($response.publicKey.challenge, $response.publicKey.user.id)) {
        $normalized = Confirm-Base64Url ([string]$value)
        if ($normalized -cne $value -or (ConvertTo-Base64Url (ConvertFrom-Base64Url $normalized)) -cne $value) {
            throw 'Graph creation options contain noncanonical challenge or user handle.'
        }
    }
    $algorithms = @($response.publicKey.pubKeyCredParams.alg)
    if ($algorithms.Count -gt 0 -and $algorithms -notcontains -7) { throw 'Graph creation options do not permit ES256.' }
    return $response.publicKey
}

function Submit-EntraSoftwareGraphRegistration {
    param([Parameter(Mandatory)][string]$UserUpn, [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$DisplayName, [Parameter(Mandatory)]$Attestation)
    $user = [uri]::EscapeDataString($UserUpn)
    $body = @{ displayName = $DisplayName; publicKeyCredential = @{
        id = $Attestation.CredentialId; response = @{ clientDataJSON = $Attestation.ClientDataJson; attestationObject = $Attestation.AttestationObject }
    } } | ConvertTo-Json -Depth 6 -Compress
    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/users/$user/authentication/fido2Methods" `
        -Method POST -Headers @{ Authorization = "Bearer $AccessToken" } -Body $body -ContentType 'application/json; charset=utf-8' `
        -MaximumRedirection 0 -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 60 -Verbose:$false -Debug:$false -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace([string]$response.id) -or $response.displayName -cne $DisplayName) {
        throw 'Graph did not confirm the submitted method.'
    }
    return $response
}

function Invoke-EntraSoftwareGraphRegistration {
    param([Parameter(Mandatory)][string]$UserUpn, [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][hashtable]$Authentication, [switch]$UseKeyVault, [string]$KeyVaultName)
    $provider = $null; $graphToken = $null; $vaultToken = $null
    try {
        $tenant = Resolve-EntraSoftwareGraphTenant -TenantId $Authentication.TenantId -UserUpn $UserUpn -UseManagedIdentity:$Authentication.UseManagedIdentity
        $Authentication.TenantId = $tenant
        $graphToken = Get-EntraSoftwareApplicationToken -Scope 'https://graph.microsoft.com/.default' @Authentication
        $options = Get-EntraSoftwareGraphCreationOptions -UserUpn $UserUpn -AccessToken $graphToken
        if ($UseKeyVault) {
            $vaultToken = Get-EntraSoftwareApplicationToken -Scope 'https://vault.azure.net/.default' @Authentication
            $provider = New-EntraKeyVaultRegistrationKey -VaultName $KeyVaultName -UserPrincipalName $UserUpn -AccessToken $vaultToken
        } else { $provider = New-SoftwarePasskeyKey }
        $attestation = New-EntraSoftwareAttestation -Provider $provider -Challenge $options.challenge -Format None
        $method = Submit-EntraSoftwareGraphRegistration -UserUpn $UserUpn -AccessToken $graphToken -DisplayName $DisplayName -Attestation $attestation
        $record = New-EntraSoftwareCredentialRecord -Provider $provider -Attestation $attestation -UserHandle $options.user.id -UserPrincipalName $options.user.name -DisplayName $DisplayName
        return [pscustomobject]@{ Credential = $record; Method = $method; TenantId = $tenant; UserPrincipalName = $UserUpn }
    } finally {
        if ($null -ne $provider -and $provider.PSObject.Properties['Key']) { Clear-SoftwarePasskeyKey $provider }
        if ($null -ne $provider -and $provider.PSObject.Properties['AccessToken']) { $provider.AccessToken = $null }
        $graphToken = $null; $vaultToken = $null
    }
}
