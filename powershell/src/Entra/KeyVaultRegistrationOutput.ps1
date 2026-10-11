function Save-EntraKeyVaultRegistrationRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Request,
        [Parameter(Mandatory)]$Attestation,
        [Parameter(Mandatory)]$KeyVaultInfo,
        [Parameter(Mandatory)][string]$DisplayName,
        [string]$OutputPath
    )
    $reference = Resolve-KeyVaultReference -VaultName $KeyVaultInfo.vaultName -KeyName $KeyVaultInfo.keyName -KeyId $KeyVaultInfo.keyId
    if ([string]$KeyVaultInfo.keyId -cnotmatch '/keys/[a-zA-Z0-9-]{1,127}/[a-fA-F0-9]{32}$') { throw 'Credential records require a versioned Key Vault key ID.' }
    if (-not $OutputPath) {
        $prefix = $Context.UserPrincipalName.Split('@')[0] -replace '[^0-9A-Za-z-]', ''
        if (-not $prefix) { $prefix = 'user' }
        $OutputPath = Join-Path (Get-Location) "${prefix}_passkey_$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    }
    $record = [ordered]@{
        credentialId = $Attestation.CredentialId; relyingParty = $Attestation.RelyingParty
        url = "https://$($Attestation.RelyingParty)"; userName = $Context.UserPrincipalName
        userHandle = $Request.UserHandle; displayName = $DisplayName; keyVault = $reference
        createdDateTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    try {
        # Historical explicit OutputPath behavior: replace an existing credential record.
        $record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8 -ErrorAction Stop
    } catch {
        $exception = [System.IO.IOException]::new('Entra enrollment was confirmed, but the credential record could not be saved. The Key Vault key and server enrollment were not rolled back. The public credential record is available in this error TargetObject for recovery.')
        $failure = [System.Management.Automation.ErrorRecord]::new($exception, 'CredentialRecordWriteFailed', [System.Management.Automation.ErrorCategory]::WriteError, [pscustomobject]$record)
        $PSCmdlet.ThrowTerminatingError($failure)
    }
    Write-Host "Credential saved to: $OutputPath"
    [pscustomobject]$record
}
