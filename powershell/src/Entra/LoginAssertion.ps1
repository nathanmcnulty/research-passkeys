function Start-EntraPasskeyLogin {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $response=Invoke-EntraLoginWebRequest -Context $Context -Uri $Context.AuthUrl
    $state=Read-EntraLoginPage -Response $response -RequireConfig -AllowNoSession
    if (-not $state.oGetCredTypeResult.Credentials.HasFido -or [string]::IsNullOrWhiteSpace($state.sFidoChallenge)) { throw 'FIDO2 authentication is unavailable.' }
    $Context.InitialState=$state
}

function New-EntraPasskeyAssertion {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    # Legacy software compatibility: these UP/UV bits are synthesized claims.
    # Local/KV signing does not establish fresh authenticator-bound user presence or verification.
    $authData=New-FidoAuthenticatorData -RpId $Context.RpId -SignCount $Context.SignCount -Flags 0x05
    $challenge=ConvertTo-Base64Url ([System.Text.Encoding]::ASCII.GetBytes($Context.InitialState.sFidoChallenge))
    $args=@{Challenge=$challenge;Origin=$Context.Origin;AuthDataBytes=$authData}
    if ($Context.KeyVaultInfo) { $args.KeyVaultInfo=$Context.KeyVaultInfo;$args.KeyVaultToken=$Context.KeyVaultToken }
    else { $args.PrivateKeyPem=$Context.PrivateKeyPem }
    try { $crypto=New-FidoSignature @args } catch { throw 'FIDO assertion generation failed; details suppressed.' }
    $Context.Assertion=[ordered]@{
        id=$Context.CredentialId;clientDataJSON=(ConvertTo-Base64Url $crypto.ClientData)
        authenticatorData=(ConvertTo-Base64Url $authData);signature=(ConvertTo-Base64Url $crypto.Signature);userHandle=$Context.UserHandle
    }
}

function Submit-EntraPasskeyAssertion {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $state=$Context.InitialState
    $body=@{
        allowedIdentities=2;canary=$state.sFT;ServerChallenge=$state.sFT
        postBackUrl=$state.urlPost;postBackUrlAad=$state.urlPostAad;postBackUrlMsa=$state.urlPostMsa
        cancelUrl=$state.urlRefresh;resumeUrl=$state.urlResume;correlationId=$state.correlationId
        credentialsJson=($state.oGetCredTypeResult.Credentials.FidoParams.AllowList -join ',')
        ctx=$state.sCtx;username=$Context.UserPrincipalName;loginCanary=$state.canary
    }
    $verify=Invoke-EntraLoginWebRequest -Context $Context -Uri 'https://login.microsoft.com/common/fido/get?uiflavor=Web' -Method Post -Body $body
    $verified=Read-EntraLoginPage -Response $verify -RequireConfig
    $payload=@{
        type=23;ps=23;assertion=($Context.Assertion | ConvertTo-Json -Compress -Depth 10)
        lmcCanary=$verified.sCrossDomainCanary;hpgrequestid=$verified.sessionId;ctx=$verified.sCtx
        canary=$verified.canary;flowToken=$verified.sFT
    }
    $first=Invoke-EntraLoginWebRequest -Context $Context -Uri 'https://login.microsoftonline.com/common/login' -Method Post -Body $payload
    $firstState=Read-EntraLoginPage -Response $first
    # A policy/consent page must be handled or refused before a second submission.
    if ($firstState.pgid) { $Context.PageState=$firstState;return }
    $payload.flowToken=$state.oGetCredTypeResult.FlowToken
    $response=Invoke-EntraLoginWebRequest -Context $Context -Uri 'https://login.microsoftonline.com/common/login?sso_reload=true' -Method Post -Body $payload
    $Context.PageState=Read-EntraLoginPage -Response $response
}
