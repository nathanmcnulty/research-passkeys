$modulePath = Join-Path $PSScriptRoot '..\modules\Passkey.Broker\Passkey.Broker.psd1'
Import-Module $modulePath -Force

AfterAll {
    Remove-Module Passkey.Broker -Force -ErrorAction SilentlyContinue
}

Describe 'Passkey.Broker public surface' {
    It 'exports exactly the seven broker commands' {
        $expected = @(
            'Connect-AzAccountWithPasskey', 'Connect-MgGraphWithPasskey', 'Connect-PasskeyBroker',
            'Disconnect-PasskeyBroker', 'Get-PasskeyAccessToken', 'Get-PasskeyBrokerContext', 'Get-PasskeyRecord'
        )
        @(Get-Command -Module Passkey.Broker | Select-Object -ExpandProperty Name | Sort-Object) | Should -Be $expected
    }
}

Describe 'Passkey.Broker behavior' {
    InModuleScope Passkey.Broker {
        BeforeEach {
            Disconnect-PasskeyBroker
            Mock Invoke-RestMethod {
                if ($Uri -like '*/api/broker/config') {
                    return [pscustomobject]@{
                        success = $true
                        tenantId = 'tenant-id'
                        tokenClientId = 'client-id'
                        tokenRedirectUri = 'http://localhost'
                        profiles = @(
                            [pscustomobject]@{ name = 'MicrosoftGraph'; defaultScopes = @('User.Read'); allowedScopes = @('User.Read') }
                            [pscustomobject]@{ name = 'AzureResourceManager'; defaultScopes = @('https://management.azure.com/user_impersonation'); allowedScopes = @('https://management.azure.com/user_impersonation') }
                        )
                    }
                }
                if ($Uri -like '*/api/passkeys/*') { return [pscustomobject]@{ success = $true; record = [pscustomobject]@{ recordId = 'record-1'; userName = 'user@contoso.com' } } }
                if ($Uri -like '*/token') {
                    return [pscustomobject]@{
                        success = $true; tokenType = 'Bearer'; accessToken = 'token-value'
                        expiresOn = '2030-01-01T00:00:00Z'; tenantId = 'tenant-id'; accountId = 'user@contoso.com'
                        profile = 'MicrosoftGraph'; scopes = @('User.Read')
                    }
                }
            }
            $key = ConvertTo-SecureString 'function-key' -AsPlainText -Force
            Connect-PasskeyBroker -Uri 'https://broker.example/api/' -FunctionKey $key | Out-Null
        }

        AfterEach { Disconnect-PasskeyBroker }

        It 'normalizes the URI and does not expose the Function key' {
            $context = Get-PasskeyBrokerContext
            $context.Uri | Should -Be 'https://broker.example'
            $context.Connected | Should -BeTrue
            $context.PSObject.Properties.Name | Should -Not -Contain 'FunctionKey'
        }

        It 'sends the Function key only as a request header' {
            Get-PasskeyRecord -RecordId 'record-1' | Out-Null
            Should -Invoke Invoke-RestMethod -ParameterFilter {
                $Uri -eq 'https://broker.example/api/passkeys/record-1' -and
                $Headers['x-functions-key'] -eq 'function-key'
            }
        }

        It 'rejects disallowed scopes before requesting a token' {
            { Get-PasskeyAccessToken -RecordId 'record-1' -Profile MicrosoftGraph -Scopes 'Directory.Read.All' } | Should -Throw '*not allowed*'
            Should -Invoke Invoke-RestMethod -ParameterFilter { $Uri -like '*/token' } -Times 0
        }

        It 'returns access tokens as SecureString values' {
            $token = Get-PasskeyAccessToken -RecordId 'record-1' -Profile MicrosoftGraph
            $token.AccessToken | Should -BeOfType ([System.Security.SecureString])
            $token.ExpiresOn | Should -BeOfType ([datetimeoffset])
        }

        It 'maps a passkey token into Connect-MgGraph' {
            function Connect-MgGraph { param($AccessToken, [switch]$NoWelcome) }
            Mock Get-PasskeyAccessToken {
                [pscustomobject]@{ AccessToken = (ConvertTo-SecureString 'graph-token' -AsPlainText -Force) }
            }
            Mock Connect-MgGraph {}
            Connect-MgGraphWithPasskey -RecordId 'record-1'
            Should -Invoke Connect-MgGraph -Times 1 -ParameterFilter { $AccessToken -is [System.Security.SecureString] -and $NoWelcome }
        }

        It 'maps a passkey token into Connect-AzAccount' {
            function Connect-AzAccount { param($AccessToken, $AccountId, $Tenant, $Subscription) }
            Mock Get-PasskeyAccessToken {
                [pscustomobject]@{
                    AccessToken = ConvertTo-SecureString 'arm-token' -AsPlainText -Force
                    AccountId = 'user@contoso.com'; TenantId = 'tenant-id'
                }
            }
            Mock Connect-AzAccount {}
            Connect-AzAccountWithPasskey -RecordId 'record-1' -SubscriptionId 'subscription-id'
            Should -Invoke Connect-AzAccount -Times 1 -ParameterFilter {
                $AccessToken -eq 'arm-token' -and $AccountId -eq 'user@contoso.com' -and
                $Tenant -eq 'tenant-id' -and $Subscription -eq 'subscription-id'
            }
        }
    }
}
