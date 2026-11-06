function New-SoftwarePasskeyKey {
    # The returned key is caller-owned. Never return this object through ordinary logging.
    $key = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7'))
    try {
        $public = $key.ExportParameters($false)
        $privateBytes = $key.ExportPkcs8PrivateKey()
        try {
            $pem = "-----BEGIN PRIVATE KEY-----`n$([Convert]::ToBase64String($privateBytes, [System.Base64FormattingOptions]::InsertLineBreaks))`n-----END PRIVATE KEY-----"
        } finally { [Array]::Clear($privateBytes, 0, $privateBytes.Length) }
        return [pscustomobject]@{ Key = $key; PublicX = [byte[]]$public.Q.X; PublicY = [byte[]]$public.Q.Y; PrivateKeyPem = $pem }
    } catch { $key.Dispose(); throw }
}

function Clear-SoftwarePasskeyKey {
    param([AllowNull()]$Provider)
    if ($null -ne $Provider) {
        if ($null -ne $Provider.Key) { $Provider.Key.Dispose(); $Provider.Key = $null }
        $property = $Provider.PSObject.Properties['PrivateKeyPem']
        if ($null -ne $property) { $Provider.PrivateKeyPem = $null }
    }
}
