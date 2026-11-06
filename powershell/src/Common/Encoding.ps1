function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

function ConvertFrom-Base64Url {
    param([string]$Base64Url)
    $base64 = $Base64Url.Replace('-', '+').Replace('_', '/')
    # Add padding
    $padding = (4 - ($base64.Length % 4)) % 4
    $base64 += '=' * $padding
    return [Convert]::FromBase64String($base64)
}

function Confirm-Base64Url {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -cnotmatch '^[A-Za-z0-9+/_-]+={0,2}$') {
        throw 'Credential identifier or user handle must be base64url/base64 text.'
    }
    $normalized = $Value.TrimEnd('=') -replace '\+','-' -replace '/','_'
    if ($normalized.Length % 4 -eq 1) { throw 'Invalid base64url length.' }
    return $normalized
}

function ConvertFrom-UuidToBase64Url {
    param([string]$Uuid)

    if ($Uuid -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        return $Uuid  # Not a UUID, return as-is
    }

    Write-Verbose "Converting UUID format credential ID to base64url"
    $hexString = $Uuid.Replace('-', '')
    $rawBytes = [byte[]]::new($hexString.Length / 2)
    for ($i = 0; $i -lt $hexString.Length; $i += 2) {
        $rawBytes[$i / 2] = [Convert]::ToByte($hexString.Substring($i, 2), 16)
    }
    $base64 = [Convert]::ToBase64String($rawBytes)
    return $base64.Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

function ConvertFrom-IeeeToDer {
    param([byte[]]$IeeeSignature)

    # IEEE P1363 format for ES256 is r || s (32 + 32 bytes)
    # DER format is: 0x30 <length> 0x02 <r-length> <r> 0x02 <s-length> <s>

    if ($IeeeSignature.Length -ne 64) {
        throw "Invalid IEEE P1363 signature length: $($IeeeSignature.Length). Expected 64 bytes for ES256."
    }

    $r = $IeeeSignature[0..31]
    $s = $IeeeSignature[32..63]

    # Remove leading zero bytes but keep at least one byte
    while ($r.Length -gt 1 -and $r[0] -eq 0) { $r = $r[1..($r.Length-1)] }
    while ($s.Length -gt 1 -and $s[0] -eq 0) { $s = $s[1..($s.Length-1)] }

    # Add leading zero if high bit is set (to keep it positive)
    if ($r[0] -ge 0x80) { $r = @(0) + $r }
    if ($s[0] -ge 0x80) { $s = @(0) + $s }

    # Build DER sequence
    $der = @(
        0x30,  # SEQUENCE tag
        ($r.Length + $s.Length + 4),  # Total length
        0x02,  # INTEGER tag for r
        $r.Length
    ) + $r + @(
        0x02,  # INTEGER tag for s
        $s.Length
    ) + $s

    return [byte[]]$der
}
