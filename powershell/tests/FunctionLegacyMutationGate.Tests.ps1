BeforeAll {
    $source = Join-Path $PSScriptRoot '..\..\function-app\powershell\keyvault-passkey-http\src'
    $httpFunctions = @(
        'DeletePasskeyCatalogRecord', 'RegisterEntraPasskeyViaTap', 'RegisterEntraPasskeyViaEstsAuth',
        'QueueEntraPasskeyRegistrationViaEstsAuth', 'RegisterOktaPasskeyViaIdxSession',
        'QueueOktaPasskeyRegistrationViaIdxSession'
    )
    $workers = @('ProcessEntraPasskeyRegistrationViaEstsAuth', 'ProcessOktaPasskeyRegistrationViaIdxSession')
    function Push-OutputBinding {
        param($Name, $Value)
        $global:capturedResponse = $Value
    }
}

AfterAll {
    Remove-Variable -Name capturedResponse -Scope Global -ErrorAction SilentlyContinue
}

Describe 'Legacy Function key mutations are inert' {
    It 'returns 501 and no-store before reading HTTP input' {
        foreach ($name in $httpFunctions) {
            $global:capturedResponse = $null
            & (Join-Path $source "$name\run.ps1") -Request $null -TriggerMetadata $null
            [int]$global:capturedResponse.StatusCode | Should -Be 501 -Because $name
            $global:capturedResponse.Headers['Cache-Control'] | Should -Be 'no-store' -Because $name
        }
    }

    It 'fails before reading queued payload' {
        foreach ($name in $workers) {
            { & (Join-Path $source "$name\run.ps1") -QueueItem $null -TriggerMetadata $null } | Should -Throw '*disabled*' -Because $name
        }
    }
}
