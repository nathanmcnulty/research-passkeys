function ConvertTo-PEMPrivateKey {
    param (
        [Parameter(Mandatory)]
        [string]$PrivateKey
    )

    # Check if it's already in PEM format
    if ($PrivateKey.Trim() -match "^-----BEGIN PRIVATE KEY-----") {
        return $PrivateKey
    }

    # Remove any whitespace
    $cleanKey = $PrivateKey.Trim() -replace "`r|`n|\s", ""

    # Replace invalid characters (if any)
    $cleanKey = $cleanKey -replace "-", "+" -replace "_", "/"

    # Wrap at 64 characters
    $wrappedKey = ""
    for ($i = 0; $i -lt $cleanKey.Length; $i += 64) {
        if ($i + 64 -lt $cleanKey.Length) {
            $wrappedKey += $cleanKey.Substring($i, 64) + "`n"
        } else {
            $wrappedKey += $cleanKey.Substring($i)
        }
    }

    $pemKey = "-----BEGIN PRIVATE KEY-----`n$wrappedKey`n-----END PRIVATE KEY-----"
    return $pemKey
}
