function New-EntraKeyVaultAttestation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$PublicX,
        [Parameter(Mandatory)][byte[]]$PublicY,
        [Parameter(Mandatory)][string]$ServerChallenge,
        [byte[]]$CredentialIdBytes,
        [string]$RelyingParty = 'login.microsoft.com'
    )
    if ($PublicX.Length -ne 32 -or $PublicY.Length -ne 32) { throw 'EC P-256 coordinates must be 32 bytes.' }
    if (-not $CredentialIdBytes) {
        $CredentialIdBytes = [byte[]]::new(32)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($CredentialIdBytes)
    }
    if ($CredentialIdBytes.Length -gt [uint16]::MaxValue) { throw 'Credential ID is too long.' }
    $coseKey = [ordered]@{ 1 = 2; 3 = -7; -1 = 1; -2 = $PublicX; -3 = $PublicY }
    $coseBytes = [byte[]](New-CBOREncoded -Value $coseKey)
    $rpHash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($RelyingParty))
    $lengthBytes = [byte[]]@(($CredentialIdBytes.Length -shr 8), ($CredentialIdBytes.Length -band 255))
    # AT only. A Key Vault key is not evidence of authenticator-bound UP or UV.
    $authData = [byte[]]($rpHash + [byte[]]@(0x40, 0, 0, 0, 0) + [byte[]]::new(16) + $lengthBytes + $CredentialIdBytes + $coseBytes)
    $clientData = [ordered]@{
        type = 'webauthn.create'
        challenge = ConvertTo-Base64Url -Bytes ([System.Text.Encoding]::UTF8.GetBytes($ServerChallenge))
        origin = "https://$RelyingParty"
        crossOrigin = $false
    } | ConvertTo-Json -Compress
    $attestation = [ordered]@{ fmt = 'none'; attStmt = [ordered]@{}; authData = $authData }
    [pscustomobject]@{
        CredentialId = ConvertTo-Base64Url -Bytes $CredentialIdBytes
        ClientDataJson = ConvertTo-Base64Url -Bytes ([System.Text.Encoding]::UTF8.GetBytes($clientData))
        AttestationObject = ConvertTo-Base64Url -Bytes ([byte[]](New-CBOREncoded -Value $attestation))
        ClientExtensionResults = ConvertTo-Base64Url -Bytes ([System.Text.Encoding]::UTF8.GetBytes('{"hmacCreateSecret":false}'))
        AuthenticatorData = $authData
        RelyingParty = $RelyingParty
    }
}
