# Synthetic Azure CLI fixtures only. The real az executable is never invoked.
BeforeAll {
    $setupScript = Join-Path $PSScriptRoot '../scripts/Setup-GitHubActionServicePrincipal.ps1'
    $readme = Get-Content (Join-Path $PSScriptRoot '../README.md') -Raw

    # A function takes precedence over any native az executable, including inside the
    # actual setup script. Unexpected commands fail closed instead of reaching Azure.
    function az {
        $arguments = @($args | ForEach-Object { [string]$_ })
        $command = $arguments -join ' '
        $global:PasskeySetupFixture.Calls += $command
        $global:LASTEXITCODE = 0
        switch -Regex ($command) {
            '^account show --output none$' { return }
            '^account show --output json$' { return '{"tenantId":"fixture-tenant"}' }
            '^ad app list --display-name .+ --output json$' {
                return ConvertTo-Json -InputObject @($global:PasskeySetupFixture.Applications) -Depth 5
            }
            '^ad sp show --id fixture-client --output json$' {
                return '{"id":"fixture-service-principal","appId":"fixture-client"}'
            }
            '^ad app federated-credential list --id fixture-application --output json$' {
                return ConvertTo-Json -InputObject @($global:PasskeySetupFixture.Credentials) -Depth 5
            }
            '^ad app federated-credential create --id fixture-application --parameters .+ --output json$' {
                $parameterFile = $arguments[[Array]::IndexOf($arguments, '--parameters') + 1]
                $definition = Get-Content -LiteralPath $parameterFile -Raw | ConvertFrom-Json
                $definition | Add-Member -NotePropertyName id -NotePropertyValue "fixture-$($global:PasskeySetupFixture.Credentials.Count)"
                $global:PasskeySetupFixture.Credentials += $definition
                return $definition | ConvertTo-Json -Depth 5
            }
            '^keyvault show --name fixture-vault --output json$' {
                return '{"id":"/fixture/vaults/fixture-vault","name":"fixture-vault"}'
            }
            '^role assignment list .+ --output json$' { return '[]' }
            '^role assignment create .+ --output json$' { return '{"id":"fixture-role-assignment"}' }
            default { throw "Unexpected Azure CLI command in offline fixture: $command" }
        }
    }

    function Invoke-SetupFixture {
        param([hashtable]$Arguments = @{})
        & $setupScript @Arguments 6>$null
    }

    function New-CredentialFixture {
        param(
            [string]$Name = 'existing-fixture',
            [string]$Subject = 'repo:contoso/automation:environment:entra-prod',
            [string]$Issuer = 'https://token.actions.githubusercontent.com',
            [AllowEmptyCollection()]
            [string[]]$Audiences = @('api://AzureADTokenExchange')
        )
        return [pscustomobject]@{
            id = 'existing-fixture-id'; name = $Name; subject = $Subject
            issuer = $Issuer; audiences = $Audiences
        }
    }
}

Describe 'OIDC setup trust boundary' {
    BeforeEach {
        $global:PasskeySetupFixture = @{ Calls = @(); Credentials = @(); Applications = @([pscustomobject]@{id='fixture-application';appId='fixture-client';displayName='action-passkey-login'}) }
        Mock Invoke-RestMethod { throw 'Unexpected HTTP in offline OIDC setup fixture.' }
        Mock Invoke-WebRequest { throw 'Unexpected HTTP in offline OIDC setup fixture.' }
    }
    AfterEach {
        # A replacement/delete path is never authorized, even in the stub.
        @($global:PasskeySetupFixture.Calls | Where-Object { $_ -match '\b(delete|update)\b' }).Count | Should -Be 0
        Should -Invoke Invoke-RestMethod -Times 0
        Should -Invoke Invoke-WebRequest -Times 0
    }
    AfterAll {
        Remove-Variable PasskeySetupFixture -Scope Global -ErrorAction SilentlyContinue
    }

    It 'fails omission before any Azure call, even with a Key Vault target' {
        { Invoke-SetupFixture @{ KeyVaultName = 'fixture-vault' } } | Should -Throw '*GitHubRepo is required*'
        $global:PasskeySetupFixture.Calls.Count | Should -Be 0
    }

    It 'requires an explicit repository even with an exact subject' {
        { Invoke-SetupFixture @{ OidcSubject = 'repo:contoso/automation:environment:entra-prod' } } | Should -Throw '*GitHubRepo is required*'
        $global:PasskeySetupFixture.Calls.Count | Should -Be 0
    }

    It 'rejects ambiguous repository inputs before Azure: <Repository>' -ForEach @(
        @{ Repository = '' }, @{ Repository = '  ' },
        @{ Repository = 'https://github.com/contoso/automation' },
        @{ Repository = 'contoso/automation/extra' },
        @{ Repository = 'contoso@123456/automation@456789' },
        @{ Repository = 'contoso/automation:environment:entra-prod' },
        @{ Repository = ' contoso/automation' }, @{ Repository = 'contoso/..' }
    ) {
        { Invoke-SetupFixture @{ GitHubRepo = $Repository } } | Should -Throw '*GitHubRepo*'
        $global:PasskeySetupFixture.Calls.Count | Should -Be 0
    }

    It 'uses the documented entra-prod environment and only then grants the requested vault role' {
        $readme | Should -Match 'environment: entra-prod'
        $readme | Should -Match "-GitHubRepo '<your-owner>/<your-workflow-repo>' -Environment 'entra-prod' -KeyVaultName '<your-key-vault-name>'"
        Invoke-SetupFixture @{ GitHubRepo = 'contoso/automation'; Environment = 'entra-prod'; KeyVaultName = 'fixture-vault' }
        $credential = $global:PasskeySetupFixture.Credentials[0]
        $credential.subject | Should -BeExactly 'repo:contoso/automation:environment:entra-prod'
        $credential.issuer | Should -BeExactly 'https://token.actions.githubusercontent.com'
        @($credential.audiences).Count | Should -Be 1
        $credential.audiences[0] | Should -BeExactly 'api://AzureADTokenExchange'
        @($global:PasskeySetupFixture.Calls | Where-Object { $_ -match '^role assignment create ' }).Count | Should -Be 1
        $creationIndex = [Array]::FindIndex([string[]]$global:PasskeySetupFixture.Calls, [Predicate[string]]{ param($c) $c -match '^ad app federated-credential create ' })
        $roleIndex = [Array]::FindIndex([string[]]$global:PasskeySetupFixture.Calls, [Predicate[string]]{ param($c) $c -match '^role assignment create ' })
        $roleIndex | Should -BeGreaterThan $creationIndex
    }

    It 'constructs immutable environment and branch subjects from paired verified IDs' {
        Invoke-SetupFixture @{ GitHubRepo = 'contoso/automation'; GitHubOwnerId = '123456'; GitHubRepositoryId = '456789'; Environment = 'entra-prod' }
        Invoke-SetupFixture @{ GitHubRepo = 'contoso/automation'; GitHubOwnerId = '123456'; GitHubRepositoryId = '456789'; Branch = 'main' }
        $global:PasskeySetupFixture.Credentials[0].subject | Should -BeExactly 'repo:contoso@123456/automation@456789:environment:entra-prod'
        $global:PasskeySetupFixture.Credentials[1].subject | Should -BeExactly 'repo:contoso@123456/automation@456789:ref:refs/heads/main'
    }

    It 'preserves exact supplied subjects: <Subject>' -ForEach @(
        @{ Subject = 'repo:contoso/automation:environment:entra-prod' },
        @{ Subject = 'repo:contoso@123456/automation@456789:environment:entra-prod' },
        @{ Subject = 'repo:contoso@123456/automation@456789:ref:refs/heads/main' },
        @{ Subject = 'repo:contoso/automation:environment:Production%3AV1' },
        @{ Subject = 'repo:contoso@123456/automation@456789:environment:entra-prod:job_workflow_ref:contoso/workflows/.github/workflows/login.yml@refs/heads/main' }
    ) {
        Invoke-SetupFixture @{ GitHubRepo = 'contoso/automation'; OidcSubject = $Subject }
        $global:PasskeySetupFixture.Credentials[0].subject | Should -BeExactly $Subject
    }

    It 'encodes environment metadata colons without altering case or other characters' {
        Invoke-SetupFixture @{ GitHubRepo = 'contoso/automation'; Environment = 'Production:V1' }
        $global:PasskeySetupFixture.Credentials[0].subject | Should -BeExactly 'repo:contoso/automation:environment:Production%3AV1'
    }

    It 'rejects unpaired or invalid immutable IDs before Azure: <Arguments>' -ForEach @(
        @{ Arguments = @{ GitHubOwnerId = '123456' } },
        @{ Arguments = @{ GitHubRepositoryId = '456789' } },
        @{ Arguments = @{ GitHubOwnerId = 'abc'; GitHubRepositoryId = '456789' } },
        @{ Arguments = @{ GitHubOwnerId = '123456'; GitHubRepositoryId = '0' } }
    ) {
        $inputArguments = @{ GitHubRepo = 'contoso/automation'; Environment = 'entra-prod' }
        foreach ($entry in $Arguments.GetEnumerator()) { $inputArguments[$entry.Key] = $entry.Value }
        { Invoke-SetupFixture $inputArguments } | Should -Throw
        $global:PasskeySetupFixture.Calls.Count | Should -Be 0
    }

    It 'rejects incompatible subject selectors before Azure: <Arguments>' -ForEach @(
        @{ Arguments = @{ Branch = 'main'; Environment = 'entra-prod' } },
        @{ Arguments = @{ Environment = 'entra-prod'; OidcSubject = 'repo:contoso/automation:environment:entra-prod' } },
        @{ Arguments = @{ Branch = 'main'; OidcSubject = 'repo:contoso/automation:ref:refs/heads/main' } },
        @{ Arguments = @{ GitHubOwnerId = '123456'; GitHubRepositoryId = '456789'; OidcSubject = 'repo:contoso/automation:environment:entra-prod' } }
    ) {
        $inputArguments = @{ GitHubRepo = 'contoso/automation' }
        foreach ($entry in $Arguments.GetEnumerator()) { $inputArguments[$entry.Key] = $entry.Value }
        { Invoke-SetupFixture $inputArguments } | Should -Throw
        $global:PasskeySetupFixture.Calls.Count | Should -Be 0
    }

    It 'rejects a foreign, malformed, or unsafe exact subject before Azure: <Subject>' -ForEach @(
        @{ Subject = 'repo:attacker/automation:environment:entra-prod' },
        @{ Subject = 'repo:contoso/other:environment:entra-prod' },
        @{ Subject = 'repo:Contoso/automation:environment:entra-prod' },
        @{ Subject = 'repo:contoso@123456/automation:environment:entra-prod' },
        @{ Subject = 'repo:contoso/automation@456789:environment:entra-prod' },
        @{ Subject = 'repo:contoso@abc/automation@456789:environment:entra-prod' },
        @{ Subject = 'repo:contoso/automation:environment:*' },
        @{ Subject = "repo:contoso/automation:environment:entra-prod`n" },
        @{ Subject = 'repo:contoso/automation:environment:entra-prod ' },
        @{ Subject = ('repo:contoso/automation:environment:' + ('x' * 601)) }
    ) {
        { Invoke-SetupFixture @{ GitHubRepo = 'contoso/automation'; OidcSubject = $Subject } } | Should -Throw
        $global:PasskeySetupFixture.Calls.Count | Should -Be 0
    }

    It 'rejects empty or unsafe generated contexts before Azure: <Arguments>' -ForEach @(
        @{ Arguments = @{ Environment = ' ' } },
        @{ Arguments = @{ Environment = 'entra-prod ' } },
        @{ Arguments = @{ Environment = "entra-prod`nextra" } },
        @{ Arguments = @{ Environment = '*' } },
        @{ Arguments = @{ Branch = '' } },
        @{ Arguments = @{ Branch = ' main' } }
    ) {
        $inputArguments = @{ GitHubRepo = 'contoso/automation' }
        foreach ($entry in $Arguments.GetEnumerator()) { $inputArguments[$entry.Key] = $entry.Value }
        { Invoke-SetupFixture $inputArguments } | Should -Throw
        $global:PasskeySetupFixture.Calls.Count | Should -Be 0
    }

    It 'does not collapse case-sensitive subjects into the same credential' {
        Invoke-SetupFixture @{ GitHubRepo = 'contoso/automation'; Environment = 'entra-prod' }
        Invoke-SetupFixture @{ GitHubRepo = 'contoso/automation'; Environment = 'Entra-Prod' }
        $global:PasskeySetupFixture.Credentials.Count | Should -Be 2
        $global:PasskeySetupFixture.Credentials[0].name | Should -Not -Be $global:PasskeySetupFixture.Credentials[1].name
        $global:PasskeySetupFixture.Credentials[1].subject | Should -BeExactly 'repo:contoso/automation:environment:Entra-Prod'
    }

    It 'keeps two repositories and slash/hyphen branch names distinct without touching prior trust' {
        foreach ($inputArguments in @(
            @{ GitHubRepo = 'contoso/repo-a'; Branch = 'main' },
            @{ GitHubRepo = 'contoso/repo-b'; Branch = 'main' },
            @{ GitHubRepo = 'contoso/repo-a'; Branch = 'feature/foo' },
            @{ GitHubRepo = 'contoso/repo-a'; Branch = 'feature-foo' }
        )) { Invoke-SetupFixture $inputArguments }
        $global:PasskeySetupFixture.Credentials.Count | Should -Be 4
        @($global:PasskeySetupFixture.Credentials.name | Select-Object -Unique).Count | Should -Be 4
        $global:PasskeySetupFixture.Credentials[0].subject | Should -BeExactly 'repo:contoso/repo-a:ref:refs/heads/main'
        $global:PasskeySetupFixture.Credentials[1].subject | Should -BeExactly 'repo:contoso/repo-b:ref:refs/heads/main'
        foreach ($credential in $global:PasskeySetupFixture.Credentials) {
            $credential.name | Should -Match '^github-[0-9a-f]{64}$'
            $credential.name.Length | Should -BeLessOrEqual 120
        }
    }

    It 'keeps the name bounded for long contexts and stable on rerun' {
        $inputArguments = @{ GitHubRepo = 'contoso/automation'; Branch = ('long-' + ('x' * 200)) }
        Invoke-SetupFixture $inputArguments
        $originalName = $global:PasskeySetupFixture.Credentials[0].name
        Invoke-SetupFixture $inputArguments
        $global:PasskeySetupFixture.Credentials.Count | Should -Be 1
        $global:PasskeySetupFixture.Credentials[0].name | Should -BeExactly $originalName
        $originalName.Length | Should -Be 71
        @($global:PasskeySetupFixture.Calls | Where-Object { $_ -match '^ad app federated-credential create ' }).Count | Should -Be 1
    }

    It 'reuses identical trust under an older name without creating a duplicate' {
        $global:PasskeySetupFixture.Credentials = @(New-CredentialFixture -Name 'github-old')
        Invoke-SetupFixture @{ GitHubRepo = 'contoso/automation'; Environment = 'entra-prod' }
        $global:PasskeySetupFixture.Credentials.Count | Should -Be 1
        @($global:PasskeySetupFixture.Calls | Where-Object { $_ -match '^ad app federated-credential create ' }).Count | Should -Be 0
    }

    It 'refuses incompatible existing trust and does not grant Key Vault access: <Mismatch>' -ForEach @(
        @{ Mismatch = 'issuer'; Overrides = @{ Issuer = 'https://attacker.invalid' } },
        @{ Mismatch = 'issuer case'; Overrides = @{ Issuer = 'https://TOKEN.actions.githubusercontent.com' } },
        @{ Mismatch = 'audience'; Overrides = @{ Audiences = @('wrong-audience') } },
        @{ Mismatch = 'audience case'; Overrides = @{ Audiences = @('api://azureadtokenexchange') } },
        @{ Mismatch = 'extra audience'; Overrides = @{ Audiences = @('api://AzureADTokenExchange', 'wrong-audience') } },
        @{ Mismatch = 'missing audience'; Overrides = @{ Audiences = @() } }
    ) {
        $global:PasskeySetupFixture.Credentials = @(New-CredentialFixture @Overrides)
        $before = $global:PasskeySetupFixture.Credentials | ConvertTo-Json -Depth 5
        { Invoke-SetupFixture @{ GitHubRepo = 'contoso/automation'; Environment = 'entra-prod'; KeyVaultName = 'fixture-vault' } } | Should -Throw '*incompatible subject, issuer, or audiences*'
        ($global:PasskeySetupFixture.Credentials | ConvertTo-Json -Depth 5) | Should -BeExactly $before
        @($global:PasskeySetupFixture.Calls | Where-Object { $_ -match '^(ad app federated-credential create|keyvault|role assignment) ' }).Count | Should -Be 0
    }

    It 'refuses a same-name subject conflict instead of deleting or replacing it' {
        Invoke-SetupFixture @{ GitHubRepo = 'contoso/automation'; Environment = 'entra-prod' }
        $global:PasskeySetupFixture.Credentials[0].subject = 'repo:contoso/another-repo:environment:entra-prod'
        $global:PasskeySetupFixture.Calls = @()
        { Invoke-SetupFixture @{ GitHubRepo = 'contoso/automation'; Environment = 'entra-prod' } } | Should -Throw '*incompatible subject, issuer, or audiences*'
        $global:PasskeySetupFixture.Credentials[0].subject | Should -BeExactly 'repo:contoso/another-repo:environment:entra-prod'
        @($global:PasskeySetupFixture.Calls | Where-Object { $_ -match '^ad app federated-credential create ' }).Count | Should -Be 0
    }
}

Describe 'Ambiguous application selection' {
    BeforeEach {
        $global:PasskeySetupFixture = @{ Calls = @(); Credentials = @(); Applications = @() }
        Mock Invoke-RestMethod { throw 'Unexpected HTTP in offline fixture.' }
        Mock Invoke-WebRequest { throw 'Unexpected HTTP in offline fixture.' }
    }
    AfterAll { Remove-Variable PasskeySetupFixture -Scope Global -ErrorAction SilentlyContinue }
    It 'rejects duplicate matching display names before any dependent read or write: <SecondName>' -ForEach @(
        @{SecondName='action-passkey-login'}, @{SecondName='ACTION-PASSKEY-LOGIN'}
    ) {
        $global:PasskeySetupFixture.Applications = @(
            [pscustomobject]@{id='first-object';appId='first-client';displayName='action-passkey-login'},
            [pscustomobject]@{id='second-object';appId='second-client';displayName=$SecondName}
        )
        { Invoke-SetupFixture @{GitHubRepo='contoso/automation';Environment='entra-prod';KeyVaultName='fixture-vault'} } | Should -Throw '*Multiple application registrations*'
        @($global:PasskeySetupFixture.Calls | Where-Object { $_ -match '^(ad sp|ad app federated-credential|keyvault|role assignment)|\b(create|delete|update)\b' }).Count | Should -Be 0
        Should -Invoke Invoke-WebRequest -Times 0
        Should -Invoke Invoke-RestMethod -Times 0
    }
}
