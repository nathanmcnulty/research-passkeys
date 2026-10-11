function ConvertTo-PlainTextValue {
    param(
        [Parameter(Mandatory = $false)]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [System.Security.SecureString]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        try {
            return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            if ($bstr -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }

    throw "PrivateKey must be either a string or SecureString. Received: $($Value.GetType().FullName)"
}

function Normalize-OptionalString {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $trimmedValue = $Value.Trim()
    if ($trimmedValue.Length -eq 0) {
        return $null
    }

    return $trimmedValue
}

function Get-HttpErrorMessage {
    param(
        [Parameter(Mandatory)]
        $ErrorRecord
    )

    # Exceptions and server bodies may echo bearer material. Never forward them to logs.
    return 'Request failed; server details suppressed.'
}

function Write-PasskeySoftwareWarning {
    Write-Warning 'Research automation only: not a FIDO-certified authenticator. These flows do not perform authenticator user presence or verification; any UP/UV flags are synthetic. Tenant policy may reject them.'
}
