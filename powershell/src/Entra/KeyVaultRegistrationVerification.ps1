function Update-EntraKeyVaultVerificationSession {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context)
    $headers = Get-EntraRegistrationHeaders -Context $Context -IncludeToken -IncludeSession
    foreach ($path in @('availablemethods', '')) {
        try {
            $uri = "$($Context.RedirectUri)/api/authenticationmethods"
            if ($path) { $uri += "/$path" }
            $response = Invoke-EntraRegistrationWebRequest -Uri $uri -Headers $headers -WebSession $Context.WebSession
            if ([int]$response.StatusCode -eq 200) { break }
        } catch { Write-Verbose 'Methods context was not refreshed.' }
    }
    try {
        $response = Invoke-EntraRegistrationRestMethod -Uri "$($Context.RedirectUri)/api/session/authorize" `
            -Method POST -Headers $headers -ContentType 'application/json' -Body '{}' -WebSession $Context.WebSession
        if ($response.isAuthorized -eq $true -and $response.sessionCtxV2) { $Context.SessionCtxV2 = [string]$response.sessionCtxV2 }
    } catch { Write-Verbose 'Keeping the existing authorized registration session.' }
}

function Assert-EntraRegistrationFinalized {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$StatusCode, [Parameter(Mandatory)]$Response)
    if ($StatusCode -lt 200 -or $StatusCode -ge 300 -or $Response.VerificationState -ne 2 -or
        ($Response.ErrorCode -and $Response.ErrorCode -ne 0)) { throw 'Registration was not confirmed successful.' }
    # DataUpdates.FidoDevices.CredentialId is an opaque service method identifier.
    # Finalization is not proof that the submitted WebAuthn credential has replicated.
    $Response
}

function Confirm-EntraRegistrationCredential {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$CredentialId,
        [ValidateRange(1,10)][int]$AttemptCount = 5, [ValidateRange(0,60)][int]$RetryDelaySeconds = 2)
    # Match the public My Sign-ins replication probe, without resubmitting attestation.
    $body = @{ Type = 18; CredentialVerification = $true
        VerificationData = (@{ CredentialId = $CredentialId } | ConvertTo-Json -Compress) } | ConvertTo-Json -Compress
    $headers = Get-EntraRegistrationHeaders -Context $Context -IncludeToken -IncludeSession
    for ($attempt = 1; $attempt -le $AttemptCount; $attempt++) {
        $response = Invoke-EntraRegistrationWebRequest -Uri "$($Context.RedirectUri)/api/authenticationmethods/verify" `
            -Method POST -Body $body -ContentType 'application/json' -Headers $headers -WebSession $Context.WebSession
        try { $json = $response.Content | ConvertFrom-Json -ErrorAction Stop }
        catch { throw 'Credential verification returned invalid JSON; details suppressed.' }
        if ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300 -or
            ($json.ErrorCode -and $json.ErrorCode -ne 0)) { throw 'Credential verification failed.' }
        if ($json.VerificationState -eq 2) {
            return [pscustomobject]@{ CredentialId = $CredentialId; VerificationState = 2 }
        }
        if ($json.VerificationState -ne 1) { throw 'Credential verification was rejected.' }
        if ($attempt -lt $AttemptCount) { Start-Sleep -Seconds $RetryDelaySeconds }
    }
    throw 'The submitted credential has not been confirmed; enrollment remains unconfirmed.'
}

function Invoke-EntraKeyVaultRegistrationVerification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Request,
        [Parameter(Mandatory)]$Attestation,
        [Parameter(Mandatory)][string]$DisplayName,
        [ValidateRange(1, 10)][int]$AttemptCount = 5,
        [ValidateRange(0, 60)][int]$RetryDelaySeconds = 2
    )
    $template = [ordered]@{
        Name = $DisplayName; Canary = $Request.Canary; AttestationObject = $Attestation.AttestationObject
        ClientDataJson = $Attestation.ClientDataJson; CredentialId = $Attestation.CredentialId
        ClientExtensionResults = $Attestation.ClientExtensionResults
    }
    $mode = 'empty'
    $headers = Get-EntraRegistrationHeaders -Context $Context -IncludeSession
    $headers['x-rff'] = 'tff,cpfaudit,enslfmg,fwdIam,pKoe,drmm,myAccSi,saap,mregph,mysigninsfido,mysigninsauthappnotification,mysigninsauthappotp,migaam,mrp,hoaref,mregextauth,mreghwoath,mregsq,premr,cepcr,ebtta,otebvpf,mysigninssetdefault,gcu,msieme,msiemedel,mdelsq,mdelhwoath,msidelauthapp,mdelph,msidelfido,msrappp,msdappp,aamp,fwdPhIam,fido2fs,psi2fs,sve,gprp,ctumaru,dhwo,legacyHwOATH,epowe,asnmfc,ppre,sspuispid,mahfc,pkrce,miseclientid,fnmosia,essvc,etmosvc,enmosia,enmosiv,enmosid,enmosisd,enmosidht,enmosiima,enmopr,asnmtabr,onmfrc,eaieci,enlnb,esiastnb,ersiemfa,duc,stffrf,svfae,gcufa,gprpfa,umarufnc,mfarae,gefmassv'
    for ($attempt = 1; $attempt -le $AttemptCount; $attempt++) {
        $verification = New-EntraKeyVaultVerificationDataJson -Template $template -PostInfoMode $mode -PostInfo $Request.PostInfo
        $body = @{ Type = 18; VerificationData = $verification } | ConvertTo-Json -Compress
        $response = $null; $json = $null
        try {
            $response = Invoke-EntraRegistrationWebRequest -Uri "$($Context.RedirectUri)/api/authenticationmethods/verify" `
                -Method POST -Body $body -ContentType 'application/json' -Headers $headers -WebSession $Context.WebSession
            $json = $response.Content | ConvertFrom-Json -ErrorAction Stop
        } catch { Write-Verbose 'Registration verification did not return a valid response.' }
        if ($json.VerificationState -eq 2) {
            $null = Assert-EntraRegistrationFinalized -StatusCode ([int]$response.StatusCode) -Response $json
            return (Confirm-EntraRegistrationCredential -Context $Context -CredentialId $Attestation.CredentialId `
                -AttemptCount $AttemptCount -RetryDelaySeconds $RetryDelaySeconds)
        }
        if ($json.ErrorCode -eq 20 -and $json.VerificationState -eq 3 -and $mode -eq 'empty' -and $Request.PostInfo) {
            $mode = 'context'
            continue
        }
        if ($attempt -lt $AttemptCount) { Start-Sleep -Seconds $RetryDelaySeconds }
    }
    throw 'Registration failed: the server did not confirm the expected credential.'
}
