# Synthetic regression fixtures only. No login entrypoint, credential provider,
# signing implementation or native network transport is invoked by this suite.
BeforeDiscovery {
    $invalidConfirmationFields = foreach ($field in @('canary', 'sFT', 'correlationId', 'sCtx')) {
        foreach ($invalid in @(
            @{ Kind = 'missing'; Value = $null; Remove = $true },
            @{ Kind = 'null'; Value = $null },
            @{ Kind = 'empty'; Value = '' },
            @{ Kind = 'whitespace'; Value = " `t`r`n " },
            @{ Kind = 'empty array'; Value = @() },
            @{ Kind = 'single-element array'; Value = @('SYNTHETIC-SECRET-ARRAY') },
            @{ Kind = 'multiple-element array'; Value = @('SYNTHETIC-SECRET-ONE', 'SYNTHETIC-SECRET-TWO') },
            @{ Kind = 'hashtable'; Value = @{ value = 'SYNTHETIC-SECRET-HASHTABLE' } },
            @{ Kind = 'object'; Value = [pscustomobject]@{ value = 'SYNTHETIC-SECRET-OBJECT' } },
            @{ Kind = 'integer'; Value = 42 },
            @{ Kind = 'zero'; Value = 0 },
            @{ Kind = 'floating point'; Value = 1.5 },
            @{ Kind = 'boolean'; Value = $true }
        )) {
            @{ Field = $field; Kind = $invalid.Kind; Value = $invalid.Value; Remove = ($invalid.Remove -eq $true) }
        }
    }
}

BeforeAll {
    $script:confirmationSource = Get-Content (Join-Path $PSScriptRoot '../PasskeyLogin.ps1') -Raw
    $tokens = $null; $script:confirmationParseErrors = $null
    $script:confirmationAst = [Management.Automation.Language.Parser]::ParseInput($script:confirmationSource, [ref]$tokens, [ref]$script:confirmationParseErrors)
    if ($script:confirmationParseErrors.Count -ne 0) { throw 'Generated action source must parse before fixtures load.' }
    # Extract only function declarations. Never dot-source the generated script
    # itself, which would invoke its real login entrypoint.
    foreach ($name in @('Assert-EntraLoginUri', 'Invoke-EntraLoginWebRequest', 'Read-EntraLoginPage', 'Resolve-EntraLoginInterrupts')) {
        $definitions = @($script:confirmationAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
        }, $false))
        if ($definitions.Count -ne 1) { throw 'Expected one generated declaration for each fixture dependency.' }
        . ([scriptblock]::Create($definitions[0].Extent.Text))
    }
    function New-ApplicationConfirmationState {
        param([string]$Page = 'CmsiInterrupt')
        return @{
            pgid = $Page
            canary = 'SYNTHETIC-SECRET-CANARY'
            sFT = 'SYNTHETIC-SECRET-FLOW-TOKEN'
            correlationId = 'SYNTHETIC-SECRET-CORRELATION'
            sCtx = 'SYNTHETIC-SECRET-CONTEXT'
            urlLogin = '/common/login'
            sessionId = 'synthetic-session'
            urlPost = 'https://example.invalid/never-submit'
        }
    }
    function Set-ApplicationConfirmationResponses {
        param([object[]]$States)
        $script:confirmationResponses = [Collections.Generic.Queue[object]]::new()
        foreach ($state in $States) { $script:confirmationResponses.Enqueue($state) }
    }
    function Assert-OneApplicationConfirmationPost {
        @($script:confirmationRequests | Where-Object {
            $_.Uri -ceq 'https://login.microsoftonline.com/appverify' -and $_.Method -ieq 'Post'
        }).Count | Should -Be 1
    }
}

Describe 'Bounded application confirmation through the generated real helper' {
    BeforeEach {
        $script:confirmationContext = @{
            ConfirmApplication = $true
            Session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            PageState = New-ApplicationConfirmationState
        }
        $script:confirmationRequests = [Collections.Generic.List[object]]::new()
        $script:confirmationTransportFailure = $false
        Set-ApplicationConfirmationResponses -States @(@{})
        Mock Invoke-RestMethod { throw 'Real HTTP is forbidden in application-confirmation fixtures.' }
        Mock Invoke-WebRequest {
            param($Uri, $Method, $Body, $WebSession, $MaximumRedirection)
            $bodyCopy = if ($null -eq $Body) { $null } else { @{} + $Body }
            $script:confirmationRequests.Add(@{
                Uri = [string]$Uri; Method = [string]$Method; Body = $bodyCopy
                WebSession = $WebSession; MaximumRedirection = $MaximumRedirection
            })
            if ($script:confirmationTransportFailure) { throw 'SYNTHETIC-SECRET-TRANSPORT-DETAIL' }
            if ($script:confirmationResponses.Count -eq 0) { throw 'Offline fixture refused an unexpected extra request.' }
            $next = $script:confirmationResponses.Dequeue()
            return @{ StatusCode = 200; Headers = @{}; Content = ($next | ConvertTo-Json -Depth 12 -Compress) }
        }
    }
    AfterEach {
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }

    It 'keeps the generated entrypoint switch opt-in and refuses CMSI when absent' {
        $parameter = @($script:confirmationAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -ceq 'ConfirmApplication' })
        $parameter.Count | Should -Be 1
        $parameter[0].DefaultValue | Should -BeNullOrEmpty
        $parameter[0].Extent.Text | Should -Match '\[switch\]'
        [void]$script:confirmationContext.Remove('ConfirmApplication')
        { Resolve-EntraLoginInterrupts -Context $script:confirmationContext } | Should -Throw '*will not submit approval*'
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }
    It 'refuses CMSI before HTTP when confirmation is explicitly false or null' -ForEach @(
        @{ Setting = $false }, @{ Setting = $null }
    ) {
        $script:confirmationContext.ConfirmApplication = $Setting
        { Resolve-EntraLoginInterrupts -Context $script:confirmationContext } | Should -Throw '*will not submit approval*'
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }
    It 'submits one exact bounded appverify request from validated string fields' {
        $original = @{} + $script:confirmationContext.PageState
        $output = @(Resolve-EntraLoginInterrupts -Context $script:confirmationContext)
        $output.Count | Should -Be 0
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly
        Assert-OneApplicationConfirmationPost
        $request = $script:confirmationRequests[0]
        $request.Uri | Should -BeExactly 'https://login.microsoftonline.com/appverify'
        $request.Method | Should -BeExactly 'Post'
        $request.MaximumRedirection | Should -Be 0
        [object]::ReferenceEquals($request.WebSession, $script:confirmationContext.Session) | Should -BeTrue
        (@($request.Body.Keys) | Sort-Object) -join ',' | Should -BeExactly 'canary,ContinueAuth,ctx,flowToken,hpgrequestid,i19,iscsrfspeedbump'
        $request.Body.ContinueAuth | Should -BeExactly 'true'
        $request.Body.iscsrfspeedbump | Should -BeExactly 'false'
        $request.Body.canary | Should -BeExactly $original.canary
        $request.Body.flowToken | Should -BeExactly $original.sFT
        $request.Body.hpgrequestid | Should -BeExactly $original.correlationId
        $request.Body.ctx | Should -BeExactly $original.sCtx
        foreach ($field in @('canary', 'flowToken', 'hpgrequestid', 'ctx')) { $request.Body[$field] | Should -BeOfType [string] }
        $request.Body.i19 | Should -BeGreaterOrEqual 1000
        $request.Body.i19 | Should -BeLessThan 9999
        $script:confirmationContext.PageState.Count | Should -Be 0
    }
    It 'rejects <Field> as <Kind> before any appverify request, without reflecting values' -ForEach $invalidConfirmationFields {
        if ($Remove) { [void]$script:confirmationContext.PageState.Remove($Field) }
        else { $script:confirmationContext.PageState[$Field] = $Value }
        $received = [Collections.Generic.List[object]]::new()
        $failure = $null
        try {
            Resolve-EntraLoginInterrupts -Context $script:confirmationContext -Verbose -Debug *>&1 | ForEach-Object { $received.Add($_) }
        } catch { $failure = $_ }
        $failure | Should -Not -BeNullOrEmpty
        $failure.Exception.ToString() | Should -Not -Match 'SYNTHETIC-SECRET'
        $failure.ToString() | Should -Not -Match 'SYNTHETIC-SECRET'
        $received.Count | Should -Be 0
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }
    It 'rejects a non-string <Field> parsed from a returned CMSI page, without appverify' -ForEach @('canary', 'sFT', 'correlationId', 'sCtx') {
        $script:confirmationContext.PageState = New-ApplicationConfirmationState KmsiInterrupt
        $cmsi = New-ApplicationConfirmationState
        $cmsi[$_] = @{ value = 'SYNTHETIC-SECRET-PARSED-OBJECT' }
        Set-ApplicationConfirmationResponses -States @($cmsi)
        { Resolve-EntraLoginInterrupts -Context $script:confirmationContext } | Should -Throw
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly
        $script:confirmationRequests[0].Uri | Should -BeExactly 'https://login.microsoftonline.com/kmsi'
        @($script:confirmationRequests | Where-Object Uri -CEQ 'https://login.microsoftonline.com/appverify').Count | Should -Be 0
    }
    It 'refuses an immediate second CMSI before a second appverify POST' {
        Set-ApplicationConfirmationResponses -States @((New-ApplicationConfirmationState))
        { Resolve-EntraLoginInterrupts -Context $script:confirmationContext } | Should -Throw
        Assert-OneApplicationConfirmationPost
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly
    }
    It 'refuses a second CMSI even after <Label>' -ForEach @(
        @{ Label = 'KMSI'; Pages = @('KmsiInterrupt') },
        @{ Label = 'ConvergedSignIn'; Pages = @('ConvergedSignIn') },
        @{ Label = 'KMSI then ConvergedSignIn'; Pages = @('KmsiInterrupt', 'ConvergedSignIn') },
        @{ Label = 'ConvergedSignIn then KMSI'; Pages = @('ConvergedSignIn', 'KmsiInterrupt') },
        @{ Label = 'alternating KMSI and ConvergedSignIn'; Pages = @('KmsiInterrupt', 'ConvergedSignIn', 'KmsiInterrupt') }
    ) {
        $states = @($Pages | ForEach-Object { New-ApplicationConfirmationState $_ })
        $states += New-ApplicationConfirmationState
        Set-ApplicationConfirmationResponses -States $states
        $failure = $null
        try { Resolve-EntraLoginInterrupts -Context $script:confirmationContext } catch { $failure = $_ }
        $failure | Should -Not -BeNullOrEmpty
        $failure.Exception.ToString() | Should -Not -Match 'SYNTHETIC-SECRET'
        Assert-OneApplicationConfirmationPost
        $script:confirmationRequests.Count | Should -Be ($Pages.Count + 1)
        for ($index = 0; $index -lt $Pages.Count; $index++) {
            $request = $script:confirmationRequests[$index + 1]
            if ($Pages[$index] -eq 'KmsiInterrupt') {
                $request.Uri | Should -BeExactly 'https://login.microsoftonline.com/kmsi'
                $request.Method | Should -BeExactly 'Post'
            } else {
                $request.Uri | Should -BeExactly 'https://login.microsoftonline.com/common/login?sessionid=synthetic-session'
                $request.Method | Should -BeExactly 'Get'
                $request.Body | Should -BeNullOrEmpty
            }
        }
    }
    It 'permits the first CMSI reached after another interrupt without treating it as a repeat' -ForEach @('KmsiInterrupt', 'ConvergedSignIn') {
        $script:confirmationContext.PageState = New-ApplicationConfirmationState $_
        Set-ApplicationConfirmationResponses -States @((New-ApplicationConfirmationState), @{})
        { Resolve-EntraLoginInterrupts -Context $script:confirmationContext } | Should -Not -Throw
        Assert-OneApplicationConfirmationPost
        Should -Invoke Invoke-WebRequest -Times 2 -Exactly
        $script:confirmationRequests[1].Uri | Should -BeExactly 'https://login.microsoftonline.com/appverify'
        $script:confirmationContext.PageState.Count | Should -Be 0
    }
    It 'stops at pending <_> after the first appverify, without consenting or bypassing policy' -ForEach @(
        'Consent', 'ConvergedConsent', 'TenantRestrictions', 'ConvergedProofUp', 'UnknownInteraction'
    ) {
        Set-ApplicationConfirmationResponses -States @((New-ApplicationConfirmationState $_))
        { Resolve-EntraLoginInterrupts -Context $script:confirmationContext } | Should -Throw '*pending interaction*'
        Assert-OneApplicationConfirmationPost
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly
    }
    It 'keeps the one-POST guard local to each fresh invocation, even with the same context' {
        { Resolve-EntraLoginInterrupts -Context $script:confirmationContext } | Should -Not -Throw
        $script:confirmationContext.PageState = New-ApplicationConfirmationState
        Set-ApplicationConfirmationResponses -States @(@{})
        { Resolve-EntraLoginInterrupts -Context $script:confirmationContext } | Should -Not -Throw
        Should -Invoke Invoke-WebRequest -Times 2 -Exactly
        @($script:confirmationRequests | Where-Object {
            $_.Uri -ceq 'https://login.microsoftonline.com/appverify' -and $_.Method -ieq 'Post'
        }).Count | Should -Be 2
    }
    It 'does not poison a later invocation after malformed confirmation state was rejected' {
        $script:confirmationContext.PageState.sFT = @('SYNTHETIC-SECRET-ARRAY')
        { Resolve-EntraLoginInterrupts -Context $script:confirmationContext } | Should -Throw
        $script:confirmationContext.PageState = New-ApplicationConfirmationState
        { Resolve-EntraLoginInterrupts -Context $script:confirmationContext } | Should -Not -Throw
        Assert-OneApplicationConfirmationPost
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly
    }
    It 'suppresses transport secrets without retrying or returning a success value' {
        $script:confirmationTransportFailure = $true
        $received = [Collections.Generic.List[object]]::new()
        $failure = $null
        try {
            Resolve-EntraLoginInterrupts -Context $script:confirmationContext -Verbose -Debug *>&1 | ForEach-Object { $received.Add($_) }
        } catch { $failure = $_ }
        $failure | Should -Not -BeNullOrEmpty
        $failure.Exception.Message | Should -BeLike '*details suppressed*'
        $failure.Exception.ToString() | Should -Not -Match 'SYNTHETIC-SECRET'
        $failure.ToString() | Should -Not -Match 'SYNTHETIC-SECRET'
        $received.Count | Should -Be 0
        Assert-OneApplicationConfirmationPost
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly
    }
}
