function New-EntraSoftwareAuthenticatorData {
    param([Parameter(Mandatory)][string]$RpId, [Parameter(Mandatory)][byte[]]$CredentialId,
        [Parameter(Mandatory)][byte[]]$PublicX, [Parameter(Mandatory)][byte[]]$PublicY, [byte]$Flags = 0x45)
    if ($RpId -cne 'login.microsoft.com' -or $CredentialId.Length -ne 32 -or $PublicX.Length -ne 32 -or $PublicY.Length -ne 32) {
        throw 'Software attestation requires the Entra RP and 32-byte P-256 coordinates/credential ID.'
    }
    $cose = [ordered]@{ [int]1 = [int]2; [int]3 = [int]-7; [int]-1 = [int]1; [int]-2 = $PublicX; [int]-3 = $PublicY }
    $bytes = [Collections.Generic.List[byte]]::new()
    $bytes.AddRange([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($RpId)))
    $bytes.Add($Flags); $bytes.AddRange([byte[]]::new(4)); $bytes.AddRange([byte[]]::new(16))
    $bytes.Add(0); $bytes.Add(32); $bytes.AddRange($CredentialId)
    $bytes.AddRange([byte[]](New-CBOREncoded $cose))
    return ,$bytes.ToArray()
}

function New-EntraSoftwareAttestation {
    param([Parameter(Mandatory)]$Provider, [Parameter(Mandatory)][string]$Challenge,
        [ValidateSet('None', 'LegacyPacked')][string]$Format = 'None', [switch]$AllowLegacySoftwareAttestation)
    if ($Format -eq 'LegacyPacked' -and -not $AllowLegacySoftwareAttestation) {
        throw 'Packed software attestation requires -AllowLegacySoftwareAttestation acknowledgement.'
    }
    $credentialBytes = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Fill($credentialBytes)
    $rpId = 'login.microsoft.com'
    # Preserved research claims: these bits are synthetic and do not establish UP/UV assurance.
    $flags = if ($Format -eq 'None') { [byte]0x5D } else { [byte]0x45 }
    $authData = New-EntraSoftwareAuthenticatorData -RpId $rpId -CredentialId $credentialBytes `
        -PublicX $Provider.PublicX -PublicY $Provider.PublicY -Flags $flags
    if ($Format -eq 'LegacyPacked') { $Challenge = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($Challenge)) }
    elseif ((Confirm-Base64Url $Challenge) -cne $Challenge -or (ConvertTo-Base64Url (ConvertFrom-Base64Url $Challenge)) -cne $Challenge) { throw 'Graph creation challenge is not canonical base64url.' }
    $clientData = [ordered]@{ type = 'webauthn.create'; challenge = $Challenge; origin = "https://$rpId"; crossOrigin = $false } | ConvertTo-Json -Compress
    $clientBytes = [Text.Encoding]::UTF8.GetBytes($clientData)
    $statement = [ordered]@{}
    $formatName = 'none'
    if ($Format -eq 'LegacyPacked') {
        $formatName = 'packed'
        # This self-signed batch certificate is compatibility research, not trusted authenticator provenance.
        $batch = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7'))
        $certificate = $null
        try {
            $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=Batch Certificate, OU=Authenticator Attestation, O=Chromium, C=US', $batch, [Security.Cryptography.HashAlgorithmName]::SHA256)
            $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddYears(1))
            [byte[]]$signed = $authData + [Security.Cryptography.SHA256]::HashData($clientBytes)
            $signature = $batch.SignData($signed, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
            $statement = [ordered]@{ alg = [int]-7; sig = [byte[]]$signature; x5c = @(,[byte[]]$certificate.RawData) }
        } finally { if ($null -ne $certificate) { $certificate.Dispose() }; $batch.Dispose() }
    }
    return [pscustomobject]@{
        CredentialId = ConvertTo-Base64Url $credentialBytes
        ClientDataJson = ConvertTo-Base64Url $clientBytes
        AttestationObject = ConvertTo-Base64Url ([byte[]](New-CBOREncoded ([ordered]@{ fmt = $formatName; attStmt = $statement; authData = [byte[]]$authData })))
        ClientExtensionResults = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes('{"hmacCreateSecret":false}'))
        RelyingParty = $rpId
        Authenticator = 'cross-platform'; Transports = 'usb'; AAGuid = '00000000-0000-0000-0000-000000000000'
    }
}
