#Requires -Version 7.6

<#
.SYNOPSIS
Reads back Azure resource-role PIM request status and active role assignment state.
.DESCRIPTION
Self-contained script. No modules or runtime downloads are required.
Acquires one ARM token per operation (or reuses an in-memory -AccessToken) and queries
Microsoft.Authorization/roleAssignmentScheduleRequests and roleAssignmentScheduleInstances
(api-version 2020-10-01) at -Scope. Returns request ID, approval ID, scope, duration, status
(such as PendingApprovalProvisioning or Provisioned), and matching active assignment state
without credentials.
.EXAMPLE
./Get-AzureResourcePimRequestStatus.ps1 -KeyFilePath ./passkey.json -Scope /providers/Microsoft.Management/managementGroups/<mg-id> -RequestId <request-guid>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [PSCustomObject]$CredentialFromPipeline,

    [Parameter(Mandatory = $true)]
    [string]$Scope,

    [Parameter(Mandatory = $false)]
    [string]$RequestId,

    [Parameter(Mandatory = $false)]
    [string]$RoleName,

    [Parameter(Mandatory = $false)]
    [string]$RoleDefinitionId,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeAllActiveAssignments,

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
Get-AzureResourcePimRequestStatus @PSBoundParameters
