function New-FidoSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Challenge,
        [Parameter(Mandatory)][string]$Origin,
        [Parameter(Mandatory)][byte[]]$AuthDataBytes,
        [string]$PrivateKeyPem,
        $KeyVaultInfo,
        [string]$KeyVaultToken
    )
    if ($AuthDataBytes.Length -ne 37) { throw 'Assertion authenticator data must be 37 bytes.' }
    $client = [ordered]@{challenge=$Challenge;crossOrigin=$false;origin=$Origin;type='webauthn.get'}
    $clientBytes = [System.Text.Encoding]::UTF8.GetBytes(($client | ConvertTo-Json -Compress))
    $clientHash = [System.Security.Cryptography.SHA256]::HashData($clientBytes)
    $digest = [System.Security.Cryptography.SHA256]::HashData([byte[]]($AuthDataBytes + $clientHash))
    if ($KeyVaultInfo) {
        # A selected Key Vault provider cannot fall back to an supplied local key.
        $signature = Invoke-KeyVaultPasskeySignHash -KeyVaultInfo $KeyVaultInfo -AccessToken $KeyVaultToken -Digest $digest
    } else {
        if ([string]::IsNullOrWhiteSpace($PrivateKeyPem)) { throw 'Local signing requires a private key.' }
        $signature = Invoke-LocalPasskeySignHash -PrivateKeyPem $PrivateKeyPem -Digest $digest
    }
    return @{ Signature=[byte[]]$signature; ClientData=$clientBytes }
}
