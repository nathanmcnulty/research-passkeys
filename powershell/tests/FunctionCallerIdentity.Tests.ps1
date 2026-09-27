BeforeAll {
    . (Join-Path $PSScriptRoot '..\..\function-app\powershell\keyvault-passkey-http\src\shared\PasskeyFunctionHelpers.ps1')
    $originalTenant = $env:PASSKEY_TENANT_ID
    $env:PASSKEY_TENANT_ID = '11111111-1111-1111-1111-111111111111'
    function New-CallerRequest {
        param(
            [string]$Provider = 'aad',
            [string]$Tenant = '11111111-1111-1111-1111-111111111111',
            [string]$Object = '22222222-2222-2222-2222-222222222222',
            [string]$HeaderProvider = 'aad',
            [object[]]$ExtraClaims = @()
        )
        $principal = @{
            auth_typ = $Provider
            claims = @(@{typ='tid';val=$Tenant}, @{typ='oid';val=$Object}) + $ExtraClaims
        }
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($principal | ConvertTo-Json -Depth 8 -Compress)))
        return [pscustomobject]@{Headers=@{'X-MS-CLIENT-PRINCIPAL'=$encoded;'X-MS-CLIENT-PRINCIPAL-IDP'=$HeaderProvider}}
    }
}

AfterAll {
    $env:PASSKEY_TENANT_ID = $originalTenant
}

Describe 'PowerShell Function caller identity' {
    It 'accepts the configured Entra tenant and object' {
        $identity = Get-PasskeyCallerIdentity -Request (New-CallerRequest)
        $identity.tenantId | Should -Be '11111111-1111-1111-1111-111111111111'
        $identity.objectId | Should -Be '22222222-2222-2222-2222-222222222222'
    }

    It 'rejects another provider or tenant' {
        { Get-PasskeyCallerIdentity -Request (New-CallerRequest -Provider 'google') } | Should -Throw
        { Get-PasskeyCallerIdentity -Request (New-CallerRequest -HeaderProvider 'google') } | Should -Throw
        { Get-PasskeyCallerIdentity -Request (New-CallerRequest -Tenant '33333333-3333-3333-3333-333333333333') } | Should -Throw
    }

    It 'rejects missing and conflicting immutable claims' {
        { Get-PasskeyCallerIdentity -Request (New-CallerRequest -Object '') } | Should -Throw
        { Get-PasskeyCallerIdentity -Request (New-CallerRequest -ExtraClaims @(@{typ='oid';val='33333333-3333-3333-3333-333333333333'})) } | Should -Throw
        { Get-PasskeyCallerIdentity -Request (New-CallerRequest -ExtraClaims @(@{typ='http://schemas.microsoft.com/identity/claims/tenantid';val='33333333-3333-3333-3333-333333333333'})) } | Should -Throw
    }
}
