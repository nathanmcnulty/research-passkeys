function Invoke-LocalPasskeySignHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrivateKeyPem,
        [Parameter(Mandatory)][byte[]]$Digest
    )
    if ($Digest.Length -ne 32) { throw 'ES256 signing requires a SHA-256 digest.' }
    $key = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $key.ImportFromPem($PrivateKeyPem)
        $parameters = $key.ExportParameters($false)
        if ($key.KeySize -ne 256 -or $parameters.Curve.Oid.Value -ne '1.2.840.10045.3.1.7') {
            throw 'The software passkey must use P-256/ES256.'
        }
        return ,$key.SignHash($Digest, [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
    } finally { $key.Dispose() }
}
