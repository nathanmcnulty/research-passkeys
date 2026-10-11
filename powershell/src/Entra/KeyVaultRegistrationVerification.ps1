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

function Assert-EntraRegistrationVerified {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$StatusCode, [Parameter(Mandatory)]$Response, [Parameter(Mandatory)][string]$ExpectedCredentialId)
    if ($StatusCode -lt 200 -or $StatusCode -ge 300 -or $Response.VerificationState -ne 2 -or
        ($Response.ErrorCode -and $Response.ErrorCode -ne 0)) { throw 'Registration was not confirmed successful.' }
    $ids = @($Response.DataUpdates.FidoDevices | ForEach-Object { [string]$_.CredentialId })
    if ($ids.Count -ne 1 -or $ids[0] -cne $ExpectedCredentialId) { throw 'Registration response did not confirm the expected credential ID.' }
    $Response
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
            return (Assert-EntraRegistrationVerified -StatusCode ([int]$response.StatusCode) -Response $json -ExpectedCredentialId $Attestation.CredentialId)
        }
        if ($json.ErrorCode -eq 20 -and $json.VerificationState -eq 3 -and $mode -eq 'empty' -and $Request.PostInfo) {
            $mode = 'context'
            continue
        }
        if ($attempt -lt $AttemptCount) { Start-Sleep -Seconds $RetryDelaySeconds }
    }
    throw 'Registration failed: the server did not confirm the expected credential.'
}
