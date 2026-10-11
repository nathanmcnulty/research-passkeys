<#
.SYNOPSIS
    Registers a FIDO2 passkey using an ESTSAUTH cookie, with the credential
    private key stored in Azure Key Vault.
.DESCRIPTION
    Explicit research command. Supports WhatIf without authentication, network or output writes.
    Generates none attestation with AT-only flags. It does not establish authenticator-bound UP/UV.
    Returns the confirmed credential record after writing its public Key Vault reference.
#>
function Register-EntraKeyVaultPasskeyViaEstsAuth {
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [object]$ESTSAuthCookie,

    [Parameter(Mandatory)]
    [string]$KeyVaultName,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$KeyVaultKeyName,

    [Parameter()]
    [string]$PasskeyDisplayName = "",

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$KeyVaultAccessToken,

    [Parameter()]
    [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0',

    [Parameter()]
    [string]$RedirectUri = 'https://mysignins.microsoft.com'
)
    if (-not $PSCmdlet.ShouldProcess("$KeyVaultName / Entra passkey enrollment", 'Authenticate, create a Key Vault key, enroll the passkey, and save its credential record')) { return }
    $context = $null; $key = $null; $token = $null; $attestation = $null
    try {
        $context = New-EntraRegistrationContext -RedirectUri $RedirectUri -UserAgent $UserAgent
        $context = Invoke-EntraRegistrationCookieAuthentication -Context $context -ESTSAuthCookie (ConvertTo-PlainTextValue $ESTSAuthCookie) -TenantId $TenantId
        $token = Get-KeyVaultToken -AccessToken $KeyVaultAccessToken
        $key = New-EntraKeyVaultRegistrationKey -VaultName $KeyVaultName -KeyName $KeyVaultKeyName -UserPrincipalName $context.UserPrincipalName -AccessToken $token
        if ([string]::IsNullOrWhiteSpace($PasskeyDisplayName)) { $PasskeyDisplayName = "pk$(Get-Random -Minimum 1000 -Maximum 10000)" }
        $context = Initialize-EntraRegistrationSession -Context $context
        $request = Initialize-EntraRegistrationRequest -Context $context
        $attestation = New-EntraKeyVaultAttestation -PublicX $key.PublicX -PublicY $key.PublicY -ServerChallenge $request.ServerChallenge
        $null = Submit-EntraRegistration -Context $context -Request $request -Attestation $attestation -DisplayName $PasskeyDisplayName
        Save-EntraKeyVaultRegistrationRecord -Context $context -Request $request -Attestation $attestation -KeyVaultInfo $key.keyVault -DisplayName $PasskeyDisplayName -OutputPath $OutputPath
    } catch {
        # Only the locally constructed, bound public-record recovery error may escape.
        if ($attestation -and $key -and $_.FullyQualifiedErrorId -like 'CredentialRecordWriteFailed,*' -and
            $_.TargetObject.credentialId -ceq $attestation.CredentialId -and
            $_.TargetObject.keyVault.keyId -ceq $key.keyVault.keyId) {
            $PSCmdlet.ThrowTerminatingError($_)
        }
        $exception = [System.InvalidOperationException]::new('Key Vault passkey registration failed; service details suppressed. A Key Vault key or server enrollment may already exist. No rollback was attempted.')
        $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new($exception, 'KeyVaultRegistrationFailed', [System.Management.Automation.ErrorCategory]::InvalidOperation, $null))
    } finally {
        Clear-EntraRegistrationContext -Context $context
        if ($key) { $key.AccessToken = $null }
        $token = $null
    }

}
