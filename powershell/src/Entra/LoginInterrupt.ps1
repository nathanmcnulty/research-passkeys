function Resolve-EntraLoginInterrupts {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $Debug=$Context.PageState
    $ConfirmApplication=$Context.ConfirmApplication
    $LastPageId = $null
    $CurrentPageId = $Debug.pgid
    $LoopCount=0
    while ($Debug.pgid -in @('KmsiInterrupt','ConvergedSignIn') -or $Debug.pgid -eq 'CmsiInterrupt') {
        if ($Debug.pgid -eq 'CmsiInterrupt' -and -not $ConfirmApplication) {
            throw 'Application confirmation is required. The unattended passkey action will not submit approval.'
        }
        $CurrentPageId=$Debug.pgid
        if (($CurrentPageId -eq $LastPageId -and $CurrentPageId -ne 'ConvergedSignIn') -or ++$LoopCount -gt 10) {
            throw 'Authentication failed: stuck in or exceeded maximum interrupt loop.'
        }
        $LastPageId=$CurrentPageId
        switch ($CurrentPageId) {
            'CmsiInterrupt' {
                $uri='https://login.microsoftonline.com/appverify';$method='Post'
                $body=@{ContinueAuth='true';i19=(Get-Random -Minimum 1000 -Maximum 9999);canary=$Debug.canary;iscsrfspeedbump='false';flowToken=$Debug.sFT;hpgrequestid=$Debug.correlationId;ctx=$Debug.sCtx}
            }
            'KmsiInterrupt' {
                $uri='https://login.microsoftonline.com/kmsi';$method='Post'
                $body=@{LoginOptions=1;type=28;ctx=$Debug.sCtx;hpgrequestid=$Debug.correlationId;flowToken=$Debug.sFT;canary=$Debug.canary;i19=4130}
            }
            'ConvergedSignIn' {
                $uriObject=[uri]::new([uri]'https://login.microsoftonline.com/',[string]$Debug.urlLogin)
                $null=Assert-EntraLoginUri $uriObject.AbsoluteUri
                if ($uriObject.Host -ine 'login.microsoftonline.com') { throw 'Untrusted ConvergedSignIn login URL.' }
                $sessionId=if ($Debug.arrSessions -and $Debug.arrSessions.Count -gt 0) { $Debug.arrSessions[0].id } else { $Debug.sessionId }
                $separator=if ($uriObject.Query) { '&' } else { '?' }
                $uri=$uriObject.AbsoluteUri+$separator+'sessionid='+[uri]::EscapeDataString([string]$sessionId)
                $method='Get';$body=$null
            }
        }
        $response=Invoke-EntraLoginWebRequest -Context $Context -Uri $uri -Method $method -Body $body
        $Debug=Read-EntraLoginPage -Response $response
    }
    # An ESTS cookie can exist while an authorization/policy interaction is pending.
    # Never auto-approve consent, MFA, tenant policy, or an unknown interaction.
    if ($Debug.pgid) { throw 'Entra login has an unsupported pending interaction; complete it interactively.' }
    $Context.PageState=$Debug
}
