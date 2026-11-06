function Resolve-EntraLoginContext {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Parameters)
    $inputValues=@{}+$Parameters
    $pipeline=$inputValues.CredentialFromPipeline
    if ($pipeline) {
        foreach ($mapping in @(@('KeyFilePath','CredentialFilePath'),@('KeyVaultClientId','ClientId'),@('KeyVaultClientSecret','ClientSecret'),@('KeyVaultTenantId','TenantId'))) {
            if (-not $inputValues[$mapping[0]] -and $pipeline.($mapping[1])) { $inputValues[$mapping[0]]=$pipeline.($mapping[1]) }
        }
    }
    if ($inputValues.KeyVaultClientSecret) { $inputValues.KeyVaultClientSecret=ConvertTo-PlainTextValue $inputValues.KeyVaultClientSecret }
    foreach ($name in @('KeyFilePath','UserPrincipalName','UserHandle','KeyVaultName','KeyVaultKeyName','KeyVaultAccessToken','KeyVaultClientId','KeyVaultTenantId','Proxy','AuthUrl')) {
        if ($inputValues.ContainsKey($name)) { $inputValues[$name]=Normalize-OptionalString $inputValues[$name] }
    }
    if ($null -ne $inputValues.CredentialIdentifier -and $inputValues.CredentialIdentifier -isnot [string]) { throw 'CredentialId must be a string.' }
    $keyData=@{}
    if ($inputValues.KeyFilePath) {
        try {
            $keyData=Get-Content -LiteralPath $inputValues.KeyFilePath -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -ErrorAction Stop
            Assert-CredentialData $keyData
        } catch { throw 'Invalid credential file. Expected a valid credential JSON object; details suppressed.' }
    }
    $user=Normalize-OptionalString ([string]($keyData.username ?? $keyData.userName ?? $keyData.userPrincipalName ?? $inputValues.UserPrincipalName))
    if (-not $user) { throw 'Missing required parameter: Username.' }
    $handle=Normalize-OptionalString ([string]($keyData.userHandle ?? $inputValues.UserHandle))
    $id=Normalize-OptionalString ([string]($keyData.credentialId ?? $inputValues.CredentialIdentifier))
    if (-not $handle -or -not $id) { throw 'Missing required credential identifier or user handle.' }
    $handle=Confirm-Base64Url $handle
    $id=Confirm-Base64Url (ConvertFrom-UuidToBase64Url $id)
    $rp=[string]($keyData.relyingParty ?? $keyData.rpId ?? $inputValues.RelyingParty)
    $rpUri=$null
    if (-not [uri]::TryCreate("https://$rp",[UriKind]::Absolute,[ref]$rpUri) -or $rpUri.Host -cne $rp -or $rpUri.Port -ne 443 -or $rpUri.UserInfo -or $rpUri.AbsolutePath -ne '/') {
        throw 'Invalid relying party identifier.'
    }
    $originUri=$null
    $origin=[string]($keyData.url ?? "https://$rp")
    if (-not [uri]::TryCreate($origin,[UriKind]::Absolute,[ref]$originUri) -or $originUri.Scheme -ne 'https' -or $originUri.Port -ne 443 -or $originUri.UserInfo -or
        ($originUri.Host -ine $rp -and -not $originUri.Host.EndsWith(".$rp",[StringComparison]::OrdinalIgnoreCase))) { throw 'Credential origin does not match its relying party.' }
    $origin=$originUri.GetLeftPart([UriPartial]::Authority)
    $AuthUrl=[string]$inputValues.AuthUrl
    try { $uri=Assert-EntraLoginUri $AuthUrl } catch { throw 'Invalid auth URL: expected the trusted Microsoft HTTPS origin.' }
    if ($uri.Host -ine 'login.microsoftonline.com') { throw 'Invalid auth URL: expected login.microsoftonline.com.' }
    $query=[System.Web.HttpUtility]::ParseQueryString($uri.Query)
    foreach ($name in @('client_id','response_type','redirect_uri')) {
        $values=@($query.GetValues($name))
        if ($values.Count -ne 1 -or [string]::IsNullOrWhiteSpace($values[0])) { throw "Invalid auth URL: missing or ambiguous $name." }
    }
    $ConfirmApplication=[bool]$inputValues.ConfirmApplication
    $ExpectedClientId=[guid]$inputValues.ExpectedClientId
    if ($ConfirmApplication) {
        $clientParameters=@($query.GetValues('client_id'))
        $requestedClient=[guid]::Empty
        if ($clientParameters.Count -ne 1 -or -not [guid]::TryParse($clientParameters[0],[ref]$requestedClient) -or $requestedClient -ne $ExpectedClientId) {
            throw 'Application confirmation requires the expected client in the authorization URL.'
        }
    }
    # Validate every credential and destination before acquiring a provider token.
    $kvInfo=$null
    $vault=$inputValues.KeyVaultName;$key=$inputValues.KeyVaultKeyName
    if ($keyData.keyVault) {
        if (-not $vault) { $vault=$keyData.keyVault.vaultName }
        if (-not $key) { $key=$keyData.keyVault.keyName }
        $kvInfo=Resolve-KeyVaultReference -VaultName $vault -KeyName $key -KeyId $keyData.keyVault.keyId
    } elseif ($vault -or $key) {
        if (-not $vault -or -not $key) { throw 'Provide both -KeyVaultName and -KeyVaultKeyName.' }
        $kvInfo=Resolve-KeyVaultReference -VaultName $vault -KeyName $key
    }
    $privatePem=$null;$token=$null
    if ($kvInfo) {
        $token=Get-KeyVaultToken -AccessToken $inputValues.KeyVaultAccessToken -TenantId $inputValues.KeyVaultTenantId -ClientId $inputValues.KeyVaultClientId -ClientSecret $inputValues.KeyVaultClientSecret
    } else {
        $privateSource=$keyData.privateKey ?? $keyData.keyValue ?? $inputValues.PrivateKey
        if (-not $privateSource) { throw 'Provide a private key or Key Vault reference.' }
        try { $privatePem=ConvertTo-PEMPrivateKey -PrivateKey (ConvertTo-PlainTextValue $privateSource) } catch { throw 'Invalid private key input; details suppressed.' }
        $privateSource=$null
    }
    $query['sso_reload']='true'
    if (-not $query.Get('login_hint')) { $query['login_hint']=$user }
    $builder=[UriBuilder]::new($uri);$builder.Query=$query.ToString()
    $session=[Microsoft.PowerShell.Commands.WebRequestSession]::new();$session.UserAgent=[string]$inputValues.UserAgent
    if ($pipeline.RegistrationTime) {
        $elapsed=((Get-Date)-[datetime]$pipeline.RegistrationTime).TotalSeconds
        if ($elapsed -ge 0 -and $elapsed -lt 30) { Start-Sleep -Seconds ([math]::Ceiling(30-$elapsed)) }
    }
    return @{
        UserPrincipalName=$user;UserHandle=$handle;CredentialId=$id;RpId=$rp;Origin=$origin
        AuthUrl=$builder.Uri.AbsoluteUri;ConfirmApplication=$ConfirmApplication;ExpectedClientId=$ExpectedClientId
        KeyVaultInfo=$kvInfo;KeyVaultToken=$token;PrivateKeyPem=$privatePem
        SignCount=[uint32]($keyData.signCount ?? $keyData.counter ?? 0);Session=$session;Proxy=$inputValues.Proxy
    }
}
