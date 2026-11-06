function Resolve-EntraSoftwareConfiguration {
    param([Parameter(Mandatory)][hashtable]$Parameters, [AllowNull()]$ConfigFromPipeline,
        [Parameter(Mandatory)][string]$ParameterSetName)
    $configuration = @{} + $Parameters
    if ($null -ne $ConfigFromPipeline) {
        foreach ($mapping in @(@('ClientId', 'ApplicationId'), @('ClientSecret', 'ClientSecret'), @('TenantId', 'TenantId'), @('KeyVaultName', 'KeyVaultName'))) {
            if (-not $configuration[$mapping[0]] -and $ConfigFromPipeline.($mapping[1])) {
                $configuration[$mapping[0]] = $ConfigFromPipeline.($mapping[1])
            }
        }
        if (-not $configuration.UseKeyVault -and $ConfigFromPipeline.UseKeyVault) { $configuration.UseKeyVault = $true }
    }
    if ($configuration.ClientSecret -and $configuration.ClientSecret -isnot [securestring]) {
        $configuration.ClientSecret = ConvertTo-SecureString ([string]$configuration.ClientSecret) -AsPlainText -Force
    }
    if ($configuration.UserUpn -notmatch '^[^\s@]+@[^\s@]+$') { throw 'UserUpn must be a UPN without whitespace.' }
    if (-not $configuration.UseManagedIdentity) {
        $client = [guid]::Empty
        if (-not [guid]::TryParse([string]$configuration.ClientId, [ref]$client) -or $client -eq [guid]::Empty) { throw 'ClientId must be a nonempty application GUID.' }
        if ($ParameterSetName -eq 'Certificate') {
            if (-not $configuration.ClientCertificatePath) { throw 'ClientCertificatePath is required.' }
        } elseif (-not $configuration.ClientSecret) { throw 'ClientSecret is required.' }
    }
    if ($configuration.TenantId) {
        $tenant = [guid]::Empty
        if (-not [guid]::TryParse([string]$configuration.TenantId, [ref]$tenant) -or $tenant -eq [guid]::Empty) { throw 'TenantId must be a nonempty GUID.' }
    }
    if ($configuration.UseKeyVault -and $configuration.KeyVaultName -notmatch '^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$') { throw 'UseKeyVault requires a valid KeyVaultName.' }
    return $configuration
}

function Get-EntraSoftwareAuthenticationParameters {
    param([Parameter(Mandatory)][hashtable]$Configuration)
    return @{
        TenantId = $Configuration.TenantId; ClientId = $Configuration.ClientId; ClientSecret = $Configuration.ClientSecret
        ClientCertificatePath = $Configuration.ClientCertificatePath; ClientCertificatePassword = $Configuration.ClientCertificatePassword
        UseManagedIdentity = [bool]$Configuration.UseManagedIdentity
    }
}
