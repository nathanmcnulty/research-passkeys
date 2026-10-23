function New-EntraSoftwareCredentialRecord {
    param([Parameter(Mandatory)]$Provider, [Parameter(Mandatory)]$Attestation,
        [Parameter(Mandatory)][string]$UserHandle, [Parameter(Mandatory)][string]$UserPrincipalName,
        [Parameter(Mandatory)][string]$DisplayName)
    if ((Confirm-Base64Url $UserHandle) -cne $UserHandle -or (ConvertTo-Base64Url (ConvertFrom-Base64Url $UserHandle)) -cne $UserHandle) { throw 'Registration user handle is not canonical base64url.' }
    $record = [ordered]@{
        credentialId = $Attestation.CredentialId; userHandle = $UserHandle; userName = $UserPrincipalName
        relyingParty = $Attestation.RelyingParty; url = "https://$($Attestation.RelyingParty)"
        signCount = 0; displayName = $DisplayName; createdDateTime = [DateTimeOffset]::UtcNow.ToString('o')
    }
    if ($Provider.PSObject.Properties['PrivateKeyPem']) { $record.privateKey = $Provider.PrivateKeyPem }
    elseif ($Provider.PSObject.Properties['keyVault']) { $record.keyVault = $Provider.keyVault }
    else { throw 'Registration provider cannot serialize a key reference.' }
    return $record
}
