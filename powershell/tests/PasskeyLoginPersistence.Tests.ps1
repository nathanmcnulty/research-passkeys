BeforeAll {
    function Invoke-EntraPasskeyLogin { param([switch]$PassThru,[switch]$IncludeAuthenticationCookie,[switch]$IncludeAuthenticationSession) }
    $scriptPath=Join-Path $PSScriptRoot '../scripts/entra/reference/Invoke-EntraPasskeyLogin.ps1'
    $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$t,[ref]$e)
    $text=Get-Content $scriptPath -Raw
    $invocation=[scriptblock]::Create($text.Substring($text.IndexOf('# Invoke public command')))
}
Describe 'Standalone explicit authentication-state persistence' {
    BeforeEach {
        foreach ($name in @('ESTSCookie','ESTSCookieName','ESTSAUTH','webSession')) {Set-Variable -Scope Global -Name $name -Value 'caller-sentinel'}
        $PersistSessionToGlobalScope=$true;$PassThru=$true;$IncludeAuthenticationCookie=$false
        Mock Invoke-EntraPasskeyLogin {throw 'SYNTHETIC-FAILED-ATTEMPT'}
    }
    AfterEach {foreach ($name in @('ESTSCookie','ESTSCookieName','ESTSAUTH','webSession')) {Remove-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue}}
    It 'clears stale authentication state on an opted-in thrown failure' {
        {& $invocation} | Should -Throw '*FAILED-ATTEMPT*'
        foreach ($name in @('ESTSCookie','ESTSCookieName','ESTSAUTH','webSession')) {Get-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue | Should -BeNullOrEmpty}
    }
    It 'preserves caller state on a normal thrown failure without persistence' {
        $PersistSessionToGlobalScope=$false
        {& $invocation} | Should -Throw '*FAILED-ATTEMPT*'
        foreach ($name in @('ESTSCookie','ESTSCookieName','ESTSAUTH','webSession')) {(Get-Variable -Scope Global -Name $name).Value | Should -BeExactly 'caller-sentinel'}
    }
    It 'retains only the new unauthenticated session when explicitly asked, never an old cookie' {
        Mock Invoke-EntraPasskeyLogin {[pscustomobject]@{Success=$false;AuthenticationCookieValue=$null;AuthenticationCookieName=$null;AuthenticationSession='new-failed-session';TokenVariable=$null;SessionVariable=$null;SessionPersistedToGlobalScope=$false}}
        $result=& $invocation
        $result.Success | Should -BeFalse
        $global:webSession | Should -BeExactly 'new-failed-session'
        foreach ($name in @('ESTSCookie','ESTSCookieName','ESTSAUTH')) {Get-Variable -Scope Global -Name $name -ErrorAction SilentlyContinue | Should -BeNullOrEmpty}
    }
}
