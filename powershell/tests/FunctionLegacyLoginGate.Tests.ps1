BeforeAll {
    $source = Join-Path $PSScriptRoot '..\..\function-app\powershell\keyvault-passkey-http\src'
    $functions = @(
        'GetEntraPasskeyAccessToken', 'LoginWithStoredEntraPasskey', 'LoginWithStoredOktaPasskey',
        'LoginWithEntraPasskey', 'LoginWithOktaPasskey', 'TestOktaPasskeyLoginViaIdxSession'
    )
    function Push-OutputBinding {
        param($Name, $Value)
        $global:capturedResponse = $Value
    }
}

AfterAll {
    Remove-Variable -Name capturedResponse -Scope Global -ErrorAction SilentlyContinue
}

Describe 'Legacy Function login and token exchange are inert' {
    It 'returns 501 and no-store before reading HTTP input or credentials' {
        foreach ($name in $functions) {
            $global:capturedResponse = $null
            & (Join-Path $source "$name\run.ps1") -Request $null -TriggerMetadata $null
            [int]$global:capturedResponse.StatusCode | Should -Be 501 -Because $name
            $global:capturedResponse.Headers['Cache-Control'] | Should -Be 'no-store' -Because $name
        }
    }
}
