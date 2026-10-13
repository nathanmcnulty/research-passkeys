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
        [ValidateSet('PASSKEY_PRIVATE_CREDENTIAL_ID','PASSKEY_PRIVATE_USER_HANDLE','PASSKEY_PRIVATE_USER_PRINCIPAL_NAME','PASSKEY_PRIVATE_KEY')][string]$FailedOrUnknownSecret,
        [AllowNull()][object]$AuthorizationFailure,
        [AllowNull()][object]$CliFailure
    )
    $names = @('PASSKEY_PRIVATE_CREDENTIAL_ID','PASSKEY_PRIVATE_USER_HANDLE','PASSKEY_PRIVATE_USER_PRINCIPAL_NAME','PASSKEY_PRIVATE_KEY')
    $confirmed = @($ConfirmedWrites | Where-Object { $_ -cin $names })
    $code = "Passkey$($Stage)Failed"
    $status = [pscustomobject]@{ Code = $code; Stage = $Stage; EnrollmentStatus = $EnrollmentStatus; ExportStatus = $ExportStatus
        ConfirmedWrites = $confirmed; FailedOrUnknownSecret = $FailedOrUnknownSecret }
    # Only locally allowlisted categories and numeric service identifiers leave the operation.
    if ($AuthorizationFailure) {
        $categories = @('TransportFailure','HttpFailure','RedirectShape','UntrustedRedirect','OAuthRejected','CallbackBinding','ConfigMissing','ConfigInvalid','ServiceRejected','SignInReturned','UnsupportedContinuation','FormMissing','FormAmbiguous','FormMethod','FormAction','FormControls','InputMissing','InputAmbiguous','DuplicateField','HiddenFieldsMissing','KmsiFieldsMissing','RedirectLimit')
        $pages = @('KmsiBroker','KmsiInterrupt','ConvergedSignIn','Consent','ConvergedConsent','CmsiInterrupt','ConvergedProofUp','Unknown')
        $status | Add-Member -NotePropertyName FailureCategory -NotePropertyValue $(if ($AuthorizationFailure.Category -is [string] -and $AuthorizationFailure.Category -cin $categories) { $AuthorizationFailure.Category } else { 'UnsupportedContinuation' })
        $http = 0; $service = 0
        $httpValue = if ([int]::TryParse([string]$AuthorizationFailure.HttpStatus, [ref]$http) -and $http -ge 100 -and $http -le 599) { $http } else { $null }
        $serviceValue = if ([int]::TryParse([string]$AuthorizationFailure.ServiceErrorCode, [ref]$service) -and $service -gt 0) { $service } else { $null }
        $status | Add-Member -NotePropertyName HttpStatus -NotePropertyValue $httpValue
        $status | Add-Member -NotePropertyName ServiceErrorCode -NotePropertyValue $serviceValue
        $status | Add-Member -NotePropertyName AadstsCode -NotePropertyValue $(if ($AuthorizationFailure.AadstsCode -is [string] -and $AuthorizationFailure.AadstsCode -cmatch '^AADSTS[0-9]{4,12}$') { $AuthorizationFailure.AadstsCode } else { $null })
        $status | Add-Member -NotePropertyName MissingField -NotePropertyValue $(if ($AuthorizationFailure.MissingField -is [string] -and $AuthorizationFailure.MissingField -cin @('sCtx','sFT','canary','correlationId','form.action','input.name','input.value')) { $AuthorizationFailure.MissingField } else { $null })
        $status | Add-Member -NotePropertyName ContinuationPage -NotePropertyValue $(if ($AuthorizationFailure.Page -is [string] -and $AuthorizationFailure.Page -cin $pages) { $AuthorizationFailure.Page } else { 'Unknown' })
    }
    if ($CliFailure -and $Stage -in @('GitHubPreflight','GitHubExport')) {
        $category = if ($CliFailure.FailureCategory -is [string] -and $CliFailure.FailureCategory -cin @('CommandMissing','StartFailed','TransportFailure','TimedOut','AuthenticationFailed','AuthorizationDenied','RepositoryUnavailable','ApiFailure','NonzeroExit')) { $CliFailure.FailureCategory } else { 'NonzeroExit' }
        $check = if ($CliFailure.CliCheck -is [string] -and $CliFailure.CliCheck -cin @('RepositoryAccess','SecretWrite','Command')) { $CliFailure.CliCheck } else { 'Command' }
        $http = 0; $exit = 0
        $status | Add-Member -NotePropertyName FailureCategory -NotePropertyValue $category
        $status | Add-Member -NotePropertyName CliCheck -NotePropertyValue $check
        $status | Add-Member -NotePropertyName HttpStatus -NotePropertyValue $(if ([int]::TryParse([string]$CliFailure.HttpStatus, [ref]$http) -and $http -ge 100 -and $http -le 599) { $http } else { $null })
        $status | Add-Member -NotePropertyName CliExitCode -NotePropertyValue $(if ([int]::TryParse([string]$CliFailure.CliExitCode, [ref]$exit)) { $exit } else { $null })
    }
    $message = "$code. Stage: $Stage. Enrollment: $EnrollmentStatus. Export: $ExportStatus. Service details suppressed."
    if ($CliFailure -and $Stage -in @('GitHubPreflight','GitHubExport')) { $message += " CLI check: $($status.CliCheck). Category: $($status.FailureCategory). HTTP: $($status.HttpStatus). Exit: $($status.CliExitCode)." }
    if ($AuthorizationFailure) { $message += " Category: $($status.FailureCategory). HTTP: $($status.HttpStatus). Service code: $($status.ServiceErrorCode). AADSTS: $($status.AadstsCode). Page: $($status.ContinuationPage). Field: $($status.MissingField)." }
    if ($EnrollmentStatus -eq 'Unconfirmed') { $message += ' A method may exist; inspect My Sign-ins before retrying.' }
    if ($EnrollmentStatus -eq 'Verified' -and $ExportStatus -ne 'NotStarted') { $message += ' Enrollment completed, but export did not finish.' }
    if ($ExportStatus -eq 'Incomplete') {
        $completed = if ($confirmed.Count) { $confirmed -join ', ' } else { '(none)' }
        $message += " Confirmed writes: $completed. Failed or unknown: $FailedOrUnknownSecret. Keep consumers paused or disabled until the complete credential is exported. No rollback was attempted; GitHub cannot return previous secret values."
    }
    return [Management.Automation.ErrorRecord]::new([InvalidOperationException]::new($message), $code, [Management.Automation.ErrorCategory]::InvalidOperation, $status)
}
