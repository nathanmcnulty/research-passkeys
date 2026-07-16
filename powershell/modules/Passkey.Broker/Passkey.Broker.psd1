@{
    RootModule = 'Passkey.Broker.psm1'
    ModuleVersion = '0.1.0'
    GUID = '6d6b254f-48f6-4768-91b1-75eef5d22c51'
    Author = 'research-passkeys contributors'
    CompanyName = 'Community Contributors'
    Copyright = '(c) research-passkeys contributors'
    Description = 'Function-key client for acquiring delegated Microsoft cloud tokens with Key Vault-backed Entra passkeys.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Connect-PasskeyBroker'
        'Get-PasskeyBrokerContext'
        'Get-PasskeyRecord'
        'Get-PasskeyAccessToken'
        'Connect-MgGraphWithPasskey'
        'Connect-AzAccountWithPasskey'
        'Disconnect-PasskeyBroker'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('Passkey', 'FIDO2', 'AzureFunctions', 'MicrosoftGraph', 'Azure')
            ProjectUri = 'https://github.com/nathanmcnulty/research-passkeys'
        }
    }
}
