function New-FidoAuthenticatorData {
    param(
        [Parameter(Mandatory)]
        [string]$RpId,
        [uint32]$SignCount = 0,
        [byte]$Flags = 0x05
    )

    # 1. RP ID Hash (32 bytes)
    $rpIdBytes = [System.Text.Encoding]::UTF8.GetBytes($RpId)
    $rpIdHash = [System.Security.Cryptography.SHA256]::HashData($rpIdBytes)

    # 2. Flags (1 byte)
    # 3. Counter (Big Endian)
    $cntBytes = [BitConverter]::GetBytes([uint32]$SignCount)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($cntBytes) }

    # Combine
    $authData = [byte[]]::new(37)
    [Array]::Copy($rpIdHash, 0, $authData, 0, 32)
    $authData[32] = $Flags
    [Array]::Copy($cntBytes, 0, $authData, 33, 4)

    return $authData
}
