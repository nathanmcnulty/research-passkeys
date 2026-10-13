function Invoke-EntraPasskeyLogin {
    <#
    .SYNOPSIS
    Performs experimental Entra authentication with a local P-256 or Key Vault signing key.
    .DESCRIPTION
    Unattended software implementation, not a FIDO-certified authenticator. UP/UV flags
    are synthetic; no authenticator user presence, verification or hardware assurance is
    provided. Tenant policy may reject this flow. No consent is approved.
    Cookie/session data is returned only by explicit request. This command sets no globals.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [PSCustomObject]$CredentialFromPipeline,

        [Parameter(Mandatory = $false)]
        [string]$KeyFilePath,

        [Alias('UserName')]
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $false)]
        [string]$UserHandle,

        [Parameter(Mandatory = $false)]
        [Alias('CredentialId')]
        $CredentialIdentifier,

        [Parameter(Mandatory = $false)]
        $PrivateKey,

        [Parameter(Mandatory = $false)]
        $RelyingParty = "login.microsoft.com",

        [Parameter(Mandatory = $false)]
        $AuthUrl = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient&scope=https://graph.microsoft.com/.default&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46",

        [switch]$ConfirmApplication,
        [guid]$ExpectedClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46',

        [Parameter(Mandatory = $false)]
        $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0',

        [Parameter(Mandatory = $false)]
        [string]$Proxy,

        # Key Vault parameters (can be provided for manual mode or to override JSON values)
        [Parameter(Mandatory = $false)]
        [string]$KeyVaultName,

        [Parameter(Mandatory = $false)]
        [string]$KeyVaultKeyName,

        [Parameter(Mandatory = $false)]
        [string]$KeyVaultAccessToken,

        [Parameter(Mandatory = $false)]
        [string]$KeyVaultClientId,

        [Parameter(Mandatory = $false)]
        [object]$KeyVaultClientSecret,

        [Parameter(Mandatory = $false)]
        [string]$KeyVaultTenantId,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeAuthenticationCookie,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeAuthenticationSession
    )
    process {
        $parameters=@{}+$PSBoundParameters
        foreach ($name in @('RelyingParty','AuthUrl','ExpectedClientId','UserAgent')) {
            if (-not $parameters.ContainsKey($name)) { $parameters[$name]=Get-Variable -Name $name -ValueOnly }
        }
        $context=$null
        try {
            $context=Resolve-EntraLoginContext -Parameters $parameters
            Write-PasskeySoftwareWarning
            Start-EntraPasskeyLogin -Context $context
            New-EntraPasskeyAssertion -Context $context
            Submit-EntraPasskeyAssertion -Context $context
            Resolve-EntraLoginInterrupts -Context $context
            $result=Complete-EntraPasskeyLogin -Context $context -IncludeAuthenticationCookie:$IncludeAuthenticationCookie -IncludeAuthenticationSession:$IncludeAuthenticationSession
            if ($PassThru) { $result }
            elseif ($result.Success) { Write-Host 'Entra authenticated session verified.' }
            else { Write-Warning 'Entra authentication could not be verified.' }
        } finally {
            if ($context) {
                # Removing references is best-effort cleanup, not guaranteed memory erasure.
                $context.PrivateKeyPem=$null;$context.KeyVaultToken=$null;$context.Assertion=$null
            }
        }
    }
}
