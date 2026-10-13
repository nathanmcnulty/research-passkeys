function Assert-GitHubPasskeyRepository {
    param([Parameter(Mandatory)][string]$Repository)
    if ($Repository -cnotmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}$' -or
        $Repository.Split('/')[1] -in @('.', '..')) {
        throw 'Repository must be an explicit github.com owner/repo name, without a URL.'
    }
}

function Get-GitHubPasskeySecretValues {
    param([Parameter(Mandatory)][object]$Credential)
    $values = [ordered]@{}
    $mapping = [ordered]@{
        PASSKEY_PRIVATE_CREDENTIAL_ID = 'credentialId'
        PASSKEY_PRIVATE_USER_HANDLE = 'userHandle'
        PASSKEY_PRIVATE_USER_PRINCIPAL_NAME = 'userName'
        PASSKEY_PRIVATE_KEY = 'privateKey'
    }
    foreach ($name in $mapping.Keys) {
        $property = $mapping[$name]
        $value = $null
        if ($Credential -is [System.Collections.IDictionary]) {
            $value = $Credential[$property]
        } else {
            $p = $Credential.PSObject.Properties[$property]
            if ($null -ne $p) { $value = $p.Value }
        }
        if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
            throw "Credential field $property must be a nonempty string."
        }
        if ([Text.Encoding]::UTF8.GetByteCount($value) -gt 49152 -or $value.Contains([char]0)) {
            throw "Credential field $property exceeds the secret size limit or contains NUL."
        }
        $values[$name] = $value
    }
    foreach ($name in @('PASSKEY_PRIVATE_CREDENTIAL_ID','PASSKEY_PRIVATE_USER_HANDLE')) {
        $s = $values[$name]
        if ($s -cnotmatch '^[A-Za-z0-9_-]+$' -or ($s.Length % 4) -eq 1) {
            throw 'Credential ID and user handle must be unpadded base64url.'
        }
        try { $bytes = [Convert]::FromBase64String($s.Replace('-','+').Replace('_','/') + ('=' * ((4 - $s.Length % 4) % 4))) }
        catch { throw 'Credential ID or user handle is not valid base64url.' }
        if ([Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_') -cne $s) {
            throw 'Credential ID or user handle is not canonical base64url.'
        }
    }
    if ($values.PASSKEY_PRIVATE_USER_PRINCIPAL_NAME -notmatch '^[^\s@]+@[^\s@]+$') {
        throw 'Credential userName must be a UPN without whitespace.'
    }
    $parameters = $null
    $key = [Security.Cryptography.ECDsa]::Create()
    try {
        $key.ImportFromPem($values.PASSKEY_PRIVATE_KEY)
        $parameters = $key.ExportParameters($true)
        if ($key.KeySize -ne 256 -or $parameters.Curve.Oid.Value -ne '1.2.840.10045.3.1.7' -or $parameters.D.Length -ne 32) {
            throw 'Wrong key type.'
        }
    } catch { throw 'Credential privateKey must contain a valid unencrypted ECDSA P-256 private PEM key.' }
    finally { $key.Dispose(); if ($null -ne $parameters -and $null -ne $parameters.D) { [Array]::Clear($parameters.D, 0, $parameters.D.Length) } }
    return $values
}

