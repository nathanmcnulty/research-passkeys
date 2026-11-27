#Requires -Version 7.6

<#
.SYNOPSIS
Validates and submits an Azure resource-role PIM SelfActivate request using ARM Authorization APIs.
.DESCRIPTION
Self-contained script. No modules or runtime downloads are required.
Acquires one ARM token per operation (retrying once via Get-EntraPasskeyAccessTokenViaDeviceCode if
ARM returns an exact Conditional Access claims challenge), discovers and validates the eligible role
and schedule ID, checks the effective activation policy at the exact requested -Scope, preserves
any eligibility condition/conditionVersion, validates via roleAssignmentScheduleRequests/validate, and
submits a SelfActivate request. Refuses by default when the exact requested scope does not require
approval unless -AllowUnapprovedActivation is specified. Never approves requests or uses AdminAssign.
When an authentication context is required by policy, validates that the active ARM token's
authentication timestamp (auth_time/iat) is within -MaxAuthenticationContextTokenAgeSeconds (default 300s /
5 minutes for Conditional Access sign-in frequency 'every time') and refreshes via passkey if older.
Supports -ValidateOnly to stop after ARM /validate and -WhatIf with no auth or network calls.
.EXAMPLE
./Request-AzureResourcePimActivation.ps1 -KeyFilePath ./passkey.json -Scope /providers/Microsoft.Management/managementGroups/<mg-id> -RoleName Owner -Duration PT1H -Justification "Maintenance window"
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [PSCustomObject]$CredentialFromPipeline,

    [Parameter(Mandatory = $true)]
    [string]$Scope,

    [Parameter(Mandatory = $true)]
    [string]$Duration,

    [Parameter(Mandatory = $true)]
    [string]$Justification,

    [Parameter(Mandatory = $false)]
    [string]$RoleName,

    [Parameter(Mandatory = $false)]
    [string]$RoleDefinitionId,

    [Parameter(Mandatory = $false)]
    [string]$ScheduleId,

    [Parameter(Mandatory = $false)]
    [string]$DiscoveryScope = '/',

    [Parameter(Mandatory = $false)]
    [string]$PrincipalId,

    [Parameter(Mandatory = $false)]
    [string]$StartDateTime,

    [Parameter(Mandatory = $false)]
    [string]$TicketNumber,

    [Parameter(Mandatory = $false)]
    [string]$TicketSystem,

    [Parameter(Mandatory = $false)]
    [string]$RequestId,

    [Parameter(Mandatory = $false)]
    [switch]$ValidateOnly,

    [Parameter(Mandatory = $false)]
    [switch]$AllowUnapprovedActivation,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 86400)]
    [int]$MaxAuthenticationContextTokenAgeSeconds = 300,

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
Request-AzureResourcePimActivation @PSBoundParameters
