function ConvertTo-Base64Url {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bytes
    )

    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Base64Url
    )

    $base64 = $Base64Url.Replace('-', '+').Replace('_', '/')
    $padding = (4 - ($base64.Length % 4)) % 4
    $base64 += '=' * $padding
    return [Convert]::FromBase64String($base64)
}

function New-CBOREncoded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Value
    )

    $bytes = [System.Collections.Generic.List[byte]]::new()

    if ($Value -is [int] -or $Value -is [long]) {
        if ($Value -ge 0) {
            if ($Value -le 23) { $bytes.Add([byte]$Value) }
            elseif ($Value -le 255) { $bytes.Add(0x18); $bytes.Add([byte]$Value) }
            elseif ($Value -le 65535) {
                $bytes.Add(0x19)
                $lenBytes = [BitConverter]::GetBytes([uint16]$Value)
                [Array]::Reverse($lenBytes)
                $bytes.AddRange([byte[]]$lenBytes)
            } else {
                $bytes.Add(0x1A)
                $lenBytes = [BitConverter]::GetBytes([uint32]$Value)
                [Array]::Reverse($lenBytes)
                $bytes.AddRange([byte[]]$lenBytes)
            }
        } else {
            $n = -1 - $Value
            if ($n -le 23) { $bytes.Add([byte](0x20 + $n)) }
            elseif ($n -le 255) { $bytes.Add(0x38); $bytes.Add([byte]$n) }
            elseif ($n -le 65535) {
                $bytes.Add(0x39)
                $lenBytes = [BitConverter]::GetBytes([uint16]$n)
                [Array]::Reverse($lenBytes)
                $bytes.AddRange([byte[]]$lenBytes)
            } else {
                $bytes.Add(0x3A)
                $lenBytes = [BitConverter]::GetBytes([uint32]$n)
                [Array]::Reverse($lenBytes)
                $bytes.AddRange([byte[]]$lenBytes)
            }
        }
    } elseif ($Value -is [string]) {
        $textBytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        if ($textBytes.Length -le 23) { $bytes.Add([byte](0x60 + $textBytes.Length)) }
        elseif ($textBytes.Length -le 255) { $bytes.Add(0x78); $bytes.Add([byte]$textBytes.Length) }
        elseif ($textBytes.Length -le 65535) {
            $bytes.Add(0x79)
            $lenBytes = [BitConverter]::GetBytes([uint16]$textBytes.Length)
            [Array]::Reverse($lenBytes)
            $bytes.AddRange([byte[]]$lenBytes)
        } else {
            $bytes.Add(0x7A)
            $lenBytes = [BitConverter]::GetBytes([uint32]$textBytes.Length)
            [Array]::Reverse($lenBytes)
            $bytes.AddRange([byte[]]$lenBytes)
        }

        $bytes.AddRange([byte[]]$textBytes)
    } elseif ($Value -is [byte[]]) {
        if ($Value.Length -le 23) { $bytes.Add([byte](0x40 + $Value.Length)) }
        elseif ($Value.Length -le 255) { $bytes.Add(0x58); $bytes.Add([byte]$Value.Length) }
        elseif ($Value.Length -le 65535) {
            $bytes.Add(0x59)
            $lenBytes = [BitConverter]::GetBytes([uint16]$Value.Length)
            [Array]::Reverse($lenBytes)
            $bytes.AddRange([byte[]]$lenBytes)
        } else {
            $bytes.Add(0x5A)
            $lenBytes = [BitConverter]::GetBytes([uint32]$Value.Length)
            [Array]::Reverse($lenBytes)
            $bytes.AddRange([byte[]]$lenBytes)
        }

        $bytes.AddRange([byte[]]$Value)
    } elseif ($Value -is [System.Array]) {
        $count = $Value.Length
        if ($count -le 23) { $bytes.Add([byte](0x80 + $count)) }
        elseif ($count -le 255) { $bytes.Add(0x98); $bytes.Add([byte]$count) }
        else {
            $bytes.Add(0x99)
            $lenBytes = [BitConverter]::GetBytes([uint16]$count)
            [Array]::Reverse($lenBytes)
            $bytes.AddRange([byte[]]$lenBytes)
        }

        foreach ($item in $Value) {
            $itemBytes = New-CBOREncoded -Value $item
            if ($itemBytes -is [byte]) { $bytes.Add($itemBytes) } else { $bytes.AddRange([byte[]]$itemBytes) }
        }
    } elseif ($Value -is [System.Collections.IDictionary]) {
        $count = $Value.Count
        if ($count -le 23) { $bytes.Add([byte](0xA0 + $count)) }
        elseif ($count -le 255) { $bytes.Add(0xB8); $bytes.Add([byte]$count) }
        else {
            $bytes.Add(0xB9)
            $lenBytes = [BitConverter]::GetBytes([uint16]$count)
            [Array]::Reverse($lenBytes)
            $bytes.AddRange([byte[]]$lenBytes)
        }

        foreach ($entry in $Value.GetEnumerator()) {
            $keyBytes = New-CBOREncoded -Value $entry.Key
            $valueBytes = New-CBOREncoded -Value $entry.Value
            if ($keyBytes -is [byte]) { $bytes.Add($keyBytes) } else { $bytes.AddRange([byte[]]$keyBytes) }
            if ($valueBytes -is [byte]) { $bytes.Add($valueBytes) } else { $bytes.AddRange([byte[]]$valueBytes) }
        }
    } else {
        throw "Unsupported CBOR value type: $($Value.GetType().FullName)"
    }

    return ,[byte[]]$bytes.ToArray()
}

Export-ModuleMember -Function ConvertTo-Base64Url, ConvertFrom-Base64Url, New-CBOREncoded
