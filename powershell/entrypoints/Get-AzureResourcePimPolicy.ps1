#Requires -Version 7.6

<#
.SYNOPSIS
Checks the effective Azure resource-role PIM activation policy at an exact ARM scope.
.DESCRIPTION
Self-contained script. No modules or runtime downloads are required.
Queries Microsoft.Authorization/roleManagementPolicyAssignments (api-version 2020-10-01) strictly at
the caller-supplied -Scope without falling back to parent management group policies. Reports whether
approval is required (IsApprovalRequired), approval stages/approvers, maximum activation duration,
justification/MFA/ticketing enablement rules, and Conditional Access authentication context claim value.
.EXAMPLE
./Get-AzureResourcePimPolicy.ps1 -KeyFilePath ./passkey.json -Scope /subscriptions/<sub-id> -RoleName Owner
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [PSCustomObject]$CredentialFromPipeline,

    [Parameter(Mandatory = $true)]
    [string]$Scope,

    [Parameter(Mandatory = $false)]
    [string]$RoleName,

    [Parameter(Mandatory = $false)]
    [string]$RoleDefinitionId,

    [Parameter(Mandatory = $false)]
    [switch]$RequireApproval,

    [Parameter(Mandatory = $false)]
    [object]$AccessToken,

    [Parameter(Mandatory = $false)]
    [string]$KeyFilePath,

    [Alias('UserName')]
    [Parameter(Mandatory = $false)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [string]$UserHandle,

    [Alias('CredentialId')]
    [Parameter(Mandatory = $false)]
    $CredentialIdentifier,

    [Parameter(Mandatory = $false)]
    $PrivateKey,

    [Parameter(Mandatory = $false)]
    [string]$RelyingParty = 'login.microsoft.com',

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46',

    [Parameter(Mandatory = $false)]
    [string]$Claims,

    [Parameter(Mandatory = $false)]
    [string]$VerificationUri = 'https://login.microsoftonline.com/common/oauth2/deviceauth',

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSeconds,

    [Parameter(Mandatory = $false)]
    [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0',

    [Parameter(Mandatory = $false)]
    [string]$Proxy,

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
    [switch]$Json
)

# Invoke public command
Get-AzureResourcePimPolicy @PSBoundParameters
