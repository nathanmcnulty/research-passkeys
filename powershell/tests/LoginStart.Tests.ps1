BeforeAll {
    . "$PSScriptRoot/../src/Entra/LoginRequest.ps1"
    . "$PSScriptRoot/../src/Entra/LoginAssertion.ps1"
}
Describe 'Login redirect diagnostics do not expose server text' {
    It 'rejects multiple, malformed and untrusted Location values' -ForEach @(
        @{Locations=@('/one','/two')}, @{Locations=@('https://[SYNTHETIC-BAD')}, @{Locations=@('https://SYNTHETIC-SECRET.example.invalid/')}
    ) {
        Mock Invoke-WebRequest { @{StatusCode=302;Headers=@{Location=$Locations}} }
        $caught=$null
        try {Invoke-EntraLoginWebRequest -Context @{Session=[Microsoft.PowerShell.Commands.WebRequestSession]::new()} -Uri 'https://login.microsoftonline.com/start'} catch {$caught=$_}
        $caught.Exception.Message | Should -Match 'redirect'
        $caught.Exception.Message | Should -Not -Match 'SYNTHETIC'
    }
}
Describe 'Initial no-session response is a bounded FIDO sign-in start' {
    BeforeEach {
        $state = @{pgid='ConvergedSignIn';sErrorCode='50058';sFT='SYNTHETIC-FLOW';sCtx='SYNTHETIC-CONTEXT';sFidoChallenge='SYNTHETIC-CHALLENGE';oGetCredTypeResult=@{Credentials=@{HasFido=$true}}}
    }
    It 'allows the initial FIDO offer but refuses the same error after assertion submission' {
        $response=@{Content=('$Config=' + ($state | ConvertTo-Json -Depth 5 -Compress) + ';')}
        (Read-EntraLoginPage -Response $response -RequireConfig -AllowNoSession).pgid | Should -Be ConvergedSignIn
        { Read-EntraLoginPage -Response $response -RequireConfig } | Should -Throw '*denied*'
    }
    It 'does not allow conflicts, missing FIDO fields or another service error' -ForEach @('error','sErrTxt','strServiceExceptionMessage','errorCode','sFT','sCtx','sFidoChallenge','HasFido','sErrorCode','pgid') {
        switch ($_) {
            HasFido { $state.oGetCredTypeResult.Credentials.HasFido=$false }
            sErrorCode { $state.sErrorCode='50126' }
            pgid { $state.pgid='ConvergedError' }
            {$_ -in @('sFT','sCtx','sFidoChallenge')} { $state[$_]='' }
            default { $state[$_]='SYNTHETIC-DENIAL' }
        }
        $response=@{Content=('$Config=' + ($state | ConvertTo-Json -Depth 5 -Compress) + ';')}
        { Read-EntraLoginPage -Response $response -RequireConfig -AllowNoSession } | Should -Throw '*denied*'
    }
    It 'requests the no-session exception only at initial authorization' {
        Mock Invoke-EntraLoginWebRequest { @{Content=('$Config=' + ($state | ConvertTo-Json -Depth 5 -Compress) + ';')} }
        $ctx=@{AuthUrl='https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize'}
        Start-EntraPasskeyLogin -Context $ctx
        $ctx.InitialState.sErrorCode | Should -Be 50058
    }
}
