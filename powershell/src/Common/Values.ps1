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

function New-PasskeyOperationError {
    param(
        [Parameter(Mandatory)][ValidateSet('GitHubPreflight','TenantDiscovery','TapSignInPage','CredentialType','TapAuthorization','TokenExchange','CookieAuthentication','OutputReservation','SessionAuthorization','RegistrationOptions','Attestation','ChallengeSubmission','CredentialSubmission','EnrollmentVerification','CredentialRecord','CredentialPersistence','GitHubExport')][string]$Stage,
        [ValidateSet('NotStarted','Unconfirmed','Verified')][string]$EnrollmentStatus = 'NotStarted',
        [ValidateSet('NotStarted','Incomplete','Complete')][string]$ExportStatus = 'NotStarted',
        [string[]]$ConfirmedWrites = @(),
        [ValidateSet('PASSKEY_PRIVATE_CREDENTIAL_ID','PASSKEY_PRIVATE_USER_HANDLE','PASSKEY_PRIVATE_USER_PRINCIPAL_NAME','PASSKEY_PRIVATE_KEY')][string]$FailedOrUnknownSecret
    )
    $names = @('PASSKEY_PRIVATE_CREDENTIAL_ID','PASSKEY_PRIVATE_USER_HANDLE','PASSKEY_PRIVATE_USER_PRINCIPAL_NAME','PASSKEY_PRIVATE_KEY')
    $confirmed = @($ConfirmedWrites | Where-Object { $_ -cin $names })
    $code = "Passkey$($Stage)Failed"
    $status = [pscustomobject]@{ Code = $code; Stage = $Stage; EnrollmentStatus = $EnrollmentStatus; ExportStatus = $ExportStatus
        ConfirmedWrites = $confirmed; FailedOrUnknownSecret = $FailedOrUnknownSecret }
    $message = "$code. Stage: $Stage. Enrollment: $EnrollmentStatus. Export: $ExportStatus. Service details suppressed."
    if ($EnrollmentStatus -eq 'Unconfirmed') { $message += ' A method may exist; inspect My Sign-ins before retrying.' }
    if ($EnrollmentStatus -eq 'Verified' -and $ExportStatus -ne 'NotStarted') { $message += ' Enrollment completed, but export did not finish.' }
    if ($ExportStatus -eq 'Incomplete') {
        $completed = if ($confirmed.Count) { $confirmed -join ', ' } else { '(none)' }
        $message += " Confirmed writes: $completed. Failed or unknown: $FailedOrUnknownSecret. Keep consumers paused or disabled until the complete credential is exported. No rollback was attempted; GitHub cannot return previous secret values."
    }
    return [Management.Automation.ErrorRecord]::new([InvalidOperationException]::new($message), $code, [Management.Automation.ErrorCategory]::InvalidOperation, $status)
}
