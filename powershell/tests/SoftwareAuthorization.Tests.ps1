BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    foreach ($path in @('Common/Encoding','Common/Values','Entra/SoftwareBrowserHeaders','Entra/SoftwareSession','Entra/SoftwareAuthorization')) { . "$repo/powershell/src/$path.ps1" }
}
Describe 'Known KMSI authorization continuation compatibility' {
    BeforeEach {
        $context = New-EntraRegistrationContext
        $script:calls = 0
        Mock Invoke-EntraRegistrationWebRequest {
            $script:calls++
            if ($script:calls -eq 1) { return @{ StatusCode=200; Content=$script:page; Headers=@{} } }
            return @{ StatusCode=302; Content=''; Headers=@{ Location="https://mysignins.microsoft.com/#code=SYNTHETIC-CODE&state=$($context.State)" } }
        }
    }
    It 'accepts a known KMSI hidden form with <Style> attributes' -ForEach @(
        @{ Style='double quoted'; Form='<form method="post" action="/kmsi"><input type="hidden" name="ctx" value="SYNTHETIC-CONTEXT"><input type="hidden" name="flowToken" value="SYNTHETIC-FLOW"></form>' },
        @{ Style='single quoted'; Form="<form method='post' action='/kmsi'><input type='hidden' name='ctx' value='SYNTHETIC-CONTEXT'><input type='hidden' name='flowToken' value='SYNTHETIC-FLOW'></form>" },
        @{ Style='spaced mixed quote'; Form="<form method = 'post' action = `"/kmsi`"><input value = 'SYNTHETIC-CONTEXT' name = `"ctx`" type = 'hidden'><input type = `"hidden`" name = 'flowToken' value = `"SYNTHETIC-FLOW`"></form>" }
    ) {
        $script:page = '$Config={"pgid":"KmsiBroker"};' + $Form
        Invoke-EntraRegistrationAuthorization -Context $context -Uri 'https://login.microsoftonline.com/common/login' -Method POST -Body 'synthetic' | Should -BeExactly 'SYNTHETIC-CODE'
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 2 -Exactly
    }
    It 'restores config-less fixed-target hidden forms without copying fields outside the form' {
        $script:page = '<form action="/kmsi"><input type="hidden" name="ctx" value="SYNTHETIC-CONTEXT"><input type="hidden" name="flowToken" value="SYNTHETIC-FLOW"></form><input type="hidden" name="ctx" value="outside-form-secret">'
        Mock Invoke-EntraRegistrationWebRequest {
            $script:calls++
            if ($script:calls -eq 1) { return @{ StatusCode=200; Content=$script:page; Headers=@{} } }
            $Uri | Should -BeExactly 'https://login.microsoftonline.com/kmsi'
            $form = [Web.HttpUtility]::ParseQueryString([string]$Body)
            $form.AllKeys.Count | Should -Be 2
            $form['ctx'] | Should -BeExactly 'SYNTHETIC-CONTEXT'
            $form['flowToken'] | Should -BeExactly 'SYNTHETIC-FLOW'
            return @{ StatusCode=302; Content=''; Headers=@{ Location="https://mysignins.microsoft.com/#code=SYNTHETIC-CODE&state=$($context.State)" } }
        }
        Invoke-EntraRegistrationAuthorization -Context $context -Uri 'https://login.microsoftonline.com/common/login' | Should -BeExactly 'SYNTHETIC-CODE'
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 2 -Exactly
    }
    It 'preserves known KMSI form behavior with a submit control and existing trusted action' {
        $script:page = '$Config={"pgid":"KmsiBroker"};<form action="/common/post?flow=kmsi"><input type="hidden" name="ctx" value="SYNTHETIC-CONTEXT"><input type="submit" name="choice" value="continue"><button>Continue</button></form>'
        Mock Invoke-EntraRegistrationWebRequest {
            $script:calls++
            if ($script:calls -eq 1) { return @{ StatusCode=200; Content=$script:page; Headers=@{} } }
            $Uri | Should -BeExactly 'https://login.microsoftonline.com/common/post?flow=kmsi'
            $form = [Web.HttpUtility]::ParseQueryString([string]$Body)
            $form.AllKeys.Count | Should -Be 1
            $form['ctx'] | Should -BeExactly 'SYNTHETIC-CONTEXT'
            return @{ StatusCode=302; Content=''; Headers=@{ Location="https://mysignins.microsoft.com/#code=SYNTHETIC-CODE&state=$($context.State)" } }
        }
        Invoke-EntraRegistrationAuthorization -Context $context -Uri 'https://login.microsoftonline.com/common/login' | Should -BeExactly 'SYNTHETIC-CODE'
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 2 -Exactly
    }
}
Describe 'Structured KMSI continuation and safe rejection reasons' {
    BeforeEach {
        $context = New-EntraRegistrationContext
        $script:calls = 0
        $script:status = 200
        $script:location = $null
        Mock Invoke-EntraRegistrationWebRequest {
            $script:calls++
            if ($script:calls -eq 1) { return @{ StatusCode=$script:status; Content=$script:page; Headers=@{ Location=$script:location } } }
            $form = [Web.HttpUtility]::ParseQueryString([string]$Body)
            $form['LoginOptions'] | Should -Be '1'
            $form['type'] | Should -Be '28'
            $form['ctx'] | Should -Be 'SYNTHETIC-CONTEXT'
            $form['hpgrequestid'] | Should -Be 'SYNTHETIC-CORRELATION'
            $form['flowToken'] | Should -Be 'SYNTHETIC-FLOW'
            $form['canary'] | Should -Be 'SYNTHETIC-CANARY'
            $form['i19'] | Should -Be '4130'
            $form.AllKeys.Count | Should -Be 7
            $Uri | Should -BeExactly 'https://login.microsoftonline.com/kmsi'
            return @{ StatusCode=302; Content=''; Headers=@{ Location="https://mysignins.microsoft.com/#code=SYNTHETIC-CODE&state=$($context.State)" } }
        }
        $config = @{ pgid='KmsiInterrupt'; sCtx='SYNTHETIC-CONTEXT'; sFT='SYNTHETIC-FLOW'; canary='SYNTHETIC-CANARY'; correlationId='SYNTHETIC-CORRELATION' }
    }
    It 'uses exactly the existing curated fixed-host KmsiInterrupt config payload' {
        $script:page = '$Config=' + ($config | ConvertTo-Json -Compress) + ';'
        Invoke-EntraRegistrationAuthorization -Context $context -Uri 'https://login.microsoftonline.com/common/login' -Method POST -Body 'SYNTHETIC-TAP' | Should -BeExactly 'SYNTHETIC-CODE'
        $context.AuthorizationFailure | Should -BeNullOrEmpty
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 2 -Exactly
    }
    It 'rejects a missing or nonscalar KMSI field without submitting a continuation' -ForEach @(
        @{ Field='sCtx'; Value=$null }, @{ Field='sFT'; Value='' }, @{ Field='canary'; Value=@('raw-secret','value') }, @{ Field='correlationId'; Value=@{ value='raw-secret' } }
    ) {
        $config[$Field] = $Value
        $script:page = '$Config=' + ($config | ConvertTo-Json -Depth 4 -Compress) + ';'
        { Invoke-EntraRegistrationAuthorization -Context $context -Uri 'https://login.microsoftonline.com/common/login' } | Should -Throw
        $context.AuthorizationFailure.Category | Should -Be KmsiFieldsMissing
        $context.AuthorizationFailure.MissingField | Should -Be $Field
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 1 -Exactly
    }
    It 'never falls back when a malformed form start exists' {
        $script:page = '$Config=' + ($config | ConvertTo-Json -Compress) + ';<form action=''/kmsi'''
        { Invoke-EntraRegistrationAuthorization -Context $context -Uri 'https://login.microsoftonline.com/common/login' } | Should -Throw
        $context.AuthorizationFailure.Category | Should -Be FormMissing
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 1 -Exactly
    }
    It 'refuses <Reason> without automatic continuation' -ForEach @(
        @{ Reason='config-less unknown target'; Page='<form method="post" action="/other"><input type="hidden" name="ctx" value="raw-secret"></form>'; Category='FormAction' },
        @{ Reason='config-less query-bearing target'; Page='<form action="/kmsi?accept=yes"><input type="hidden" name="ctx" value="raw-secret"></form>'; Category='FormAction' },
        @{ Reason='config-less interactive input'; Page='<form action="/kmsi"><input type="hidden" name="ctx" value="raw-secret"><input type="submit" name="accept" value="yes"></form>'; Category='FormControls' },
        @{ Reason='config-less interactive button'; Page='<form action="/kmsi"><input type="hidden" name="ctx" value="raw-secret"><button>Accept</button></form>'; Category='FormControls' },
        @{ Reason='config-less no form'; Page='raw-secret'; Category='ConfigMissing' },
        @{ Reason='invalid JSON config'; Page='$Config={invalid};'; Category='ConfigInvalid' },
        @{ Reason='consent'; Page='$Config={"pgid":"Consent"};<form action="/consent"><input type="hidden" name="accept" value="yes"></form>'; Category='UnsupportedContinuation' },
        @{ Reason='policy/proof-up'; Page='$Config={"pgid":"ConvergedProofUp"};'; Category='UnsupportedContinuation' },
        @{ Reason='unrecognized server page name'; Page='$Config={"pgid":"SYNTHETIC-TAP"};'; Category='UnsupportedContinuation' },
        @{ Reason='nonscalar page identifier'; Page='$Config={"pgid":["KmsiInterrupt","raw-secret"],"sCtx":"ctx","sFT":"flow","canary":"canary","correlationId":"id"};'; Category='UnsupportedContinuation' },
        @{ Reason='returned login without a service code'; Page='$Config={"pgid":"ConvergedSignIn"};'; Category='SignInReturned' },
        @{ Reason='duplicate forms'; Page='$Config={"pgid":"KmsiBroker"};<form action="/kmsi"></form><form action="/kmsi"></form>'; Category='FormAmbiguous' },
        @{ Reason='duplicate action attribute'; Page='$Config={"pgid":"KmsiBroker"};<form action="/kmsi" action="/other"></form>'; Category='FormAmbiguous' },
        @{ Reason='missing action'; Page='$Config={"pgid":"KmsiBroker"};<form method="post"></form>'; Category='FormAction' },
        @{ Reason='wrong method'; Page='$Config={"pgid":"KmsiBroker"};<form method="get" action="/kmsi"></form>'; Category='FormMethod' },
        @{ Reason='untrusted action'; Page='$Config={"pgid":"KmsiBroker"};<form action="https://evil.invalid/collect"></form>'; Category='FormAction' },
        @{ Reason='duplicate hidden field'; Page='$Config={"pgid":"KmsiBroker"};<form action="/kmsi"><input type="hidden" name="ctx" value="raw-secret"><input type="hidden" name="ctx" value="other-secret"></form>'; Category='DuplicateField' },
        @{ Reason='missing input value'; Page='$Config={"pgid":"KmsiBroker"};<form action="/kmsi"><input type="hidden" name="ctx"></form>'; Category='InputMissing' },
        @{ Reason='no hidden fields'; Page='$Config={"pgid":"KmsiBroker"};<form action="/kmsi"></form>'; Category='HiddenFieldsMissing' }
    ) {
        $script:page = $Page
        { Invoke-EntraRegistrationAuthorization -Context $context -Uri 'https://login.microsoftonline.com/common/login' } | Should -Throw
        $context.AuthorizationFailure.Category | Should -Be $Category
        $safe = (New-PasskeyOperationError -Stage TapAuthorization -AuthorizationFailure $context.AuthorizationFailure).TargetObject
        ($safe | ConvertTo-Json -Depth 4) | Should -Not -Match 'SYNTHETIC|raw-secret|other-secret|evil.invalid'
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 1 -Exactly
    }
    It 'preserves only numeric HTTP AADSTS and service codes from a rejection' {
        $script:page = '$Config={"pgid":"KmsiInterrupt","iErrorCode":50126,"strServiceExceptionMessage":"AADSTS50126: raw-secret SYNTHETIC-TAP bearer-token Cookie=private"};'
        { Invoke-EntraRegistrationAuthorization -Context $context -Uri 'https://login.microsoftonline.com/common/login' } | Should -Throw
        $safe = New-PasskeyOperationError -Stage TapAuthorization -AuthorizationFailure $context.AuthorizationFailure
        $safe.TargetObject.FailureCategory | Should -Be ServiceRejected
        $safe.TargetObject.HttpStatus | Should -Be 200
        $safe.TargetObject.ServiceErrorCode | Should -Be 50126
        $safe.TargetObject.AadstsCode | Should -Be AADSTS50126
        $safe.TargetObject.ContinuationPage | Should -Be KmsiInterrupt
        $safe | Out-String | Should -Not -Match 'SYNTHETIC|raw-secret|bearer-token|Cookie=private'
        $safe.Exception.InnerException | Should -BeNullOrEmpty
        Should -Invoke Invoke-EntraRegistrationWebRequest -Times 1 -Exactly
    }
    It 'retains a failed HTTP status without logging response content' {
        $script:status = 503; $script:page = 'raw-secret SYNTHETIC-TAP'
        { Invoke-EntraRegistrationAuthorization -Context $context -Uri 'https://login.microsoftonline.com/common/login' } | Should -Throw
        $safe = New-PasskeyOperationError -Stage TapAuthorization -AuthorizationFailure $context.AuthorizationFailure
        $safe.TargetObject.FailureCategory | Should -Be HttpFailure
        $safe.TargetObject.HttpStatus | Should -Be 503
        $safe | Out-String | Should -Not -Match 'SYNTHETIC|raw-secret'
    }
    It 'retains a bounded AADSTS identifier from OAuth rejection without description or URL' {
        $script:status = 302; $script:page = ''
        $script:location = 'https://mysignins.microsoft.com/#error=access_denied&error_description=AADSTS53003%3A%20raw-secret%20SYNTHETIC-TAP&state=' + $context.State
        { Invoke-EntraRegistrationAuthorization -Context $context -Uri 'https://login.microsoftonline.com/common/login' } | Should -Throw
        $safe = New-PasskeyOperationError -Stage TapAuthorization -AuthorizationFailure $context.AuthorizationFailure
        $safe.TargetObject.FailureCategory | Should -Be OAuthRejected
        $safe.TargetObject.AadstsCode | Should -Be AADSTS53003
        $safe | Out-String | Should -Not -Match 'SYNTHETIC|raw-secret|mysignins.microsoft.com|access_denied'
    }
    It 'does not retain arrays containing allowlisted diagnostic values' {
        $details = [pscustomobject]@{ Category=@('HttpFailure','raw-secret'); HttpStatus=503; ServiceErrorCode=0
            AadstsCode=@('AADSTS50126','raw-secret'); Page=@('KmsiInterrupt','raw-secret'); MissingField=@('sCtx','raw-secret') }
        $safe = New-PasskeyOperationError -Stage TapAuthorization -AuthorizationFailure $details
        $safe.TargetObject.FailureCategory | Should -Be UnsupportedContinuation
        $safe.TargetObject.ContinuationPage | Should -Be Unknown
        $safe.TargetObject.AadstsCode | Should -BeNullOrEmpty
        $safe.TargetObject.MissingField | Should -BeNullOrEmpty
        $safe | Out-String | Should -Not -Match 'raw-secret'
    }
}
