<#
.SYNOPSIS
    Sets up Azure resources and permissions for Key Vault-backed passkey registration.
.DESCRIPTION
    Explicit research command. Supports WhatIf without authentication, network or output writes.
    Can provision resources and grant app permissions. Client secret creation requires -PassThru.
    Use -SkipSecret or -SkipServicePrincipal when no new client secret is needed.
#>
function Initialize-EntraPasskeyKeyVault {
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "rg-passkey-keyvault",

    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName,

    [Parameter(Mandatory = $false)]
    [string]$Location = "eastus",

    [Parameter(Mandatory = $false)]
    [string]$ServicePrincipalName = "KeyVault-Passkey-Service",

    [Parameter(Mandatory = $false)]
    [ValidateSet("standard", "premium")]
    [string]$KeyVaultSku = "standard",

    [Parameter(Mandatory = $false)]
    [bool]$EnablePurgeProtection = $true,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 24)]
    [int]$SecretExpirationMonths = 12,

    [Parameter(Mandatory = $false)]
    [switch]$SkipServicePrincipal,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSecret,

    [Parameter(Mandatory = $false)]
    [switch]$SkipKeyVault,

    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)
    if ($SkipServicePrincipal -and $SkipKeyVault) { throw 'Cannot skip both service-principal and Key Vault provisioning.' }
    if (-not $PSCmdlet.ShouldProcess("$ServicePrincipalName / $KeyVaultName", 'Connect, provision Azure and Graph resources, grant permissions, and generate a client secret unless skipped')) { return }
    if (-not $SkipServicePrincipal -and -not $SkipSecret -and -not $PassThru) {
        throw 'Client secret creation requires -PassThru to return its unrecoverable value. Otherwise specify -SkipSecret or -SkipServicePrincipal. No provisioning was started.'
    }
    $context = $null; $application = $null; $secret = $null
    try {
        if ($SkipServicePrincipal -and $SkipSecret) { Write-Warning 'SkipSecret is redundant when SkipServicePrincipal is set.' }
        if (-not $SkipKeyVault) {
            if (-not $KeyVaultName) { $KeyVaultName = "kv-passkey-$(Get-Random -Minimum 1000 -Maximum 9999)" }
            $null = Resolve-KeyVaultReference -VaultName $KeyVaultName -KeyName 'provisioning-validation'
        }
        $context = Get-EntraKeyVaultProvisioningContext -SubscriptionId $SubscriptionId -SkipKeyVault:$SkipKeyVault
        $application = $null; $secret = $null
        if (-not $SkipServicePrincipal) {
            $application = Initialize-EntraKeyVaultProvisioningApplication -ServicePrincipalName $ServicePrincipalName -CanGrantConsent $context.CanGrantConsent
        }
        if (-not $SkipKeyVault) {
            Initialize-EntraKeyVaultProvisioningResourceGroup -SubscriptionId $context.SubscriptionId -ResourceGroupName $ResourceGroupName -Location $Location
            $scope = Initialize-EntraKeyVaultProvisioningVault -SubscriptionId $context.SubscriptionId -TenantId $context.TenantId -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -Location $Location -Sku $KeyVaultSku -EnablePurgeProtection $EnablePurgeProtection
            if ($application) { Initialize-EntraKeyVaultProvisioningRole -SubscriptionId $context.SubscriptionId -VaultScope $scope -ServicePrincipalId $application.ServicePrincipalId }
        }
        if ($application -and -not $SkipSecret) {
            $secret = New-EntraKeyVaultProvisioningSecret -ApplicationObjectId $application.ApplicationObjectId -ApplicationId $application.ApplicationId -TenantId $context.TenantId -ExpirationMonths $SecretExpirationMonths -SkipKeyVault:$SkipKeyVault
            Write-Host "Client secret created; expires $($secret.SecretExpiration)."
        }
        Write-Host 'Explicit provisioning workflow complete. This research sample does not establish production readiness.'
        if ($PassThru) {
            [pscustomobject]@{
                TenantId = $context.TenantId; SubscriptionId = $context.SubscriptionId
                ResourceGroupName = if (-not $SkipKeyVault) { $ResourceGroupName } else { $null }
                KeyVaultName = if (-not $SkipKeyVault) { $KeyVaultName } else { $null }
                KeyVaultSku = if (-not $SkipKeyVault) { $KeyVaultSku } else { $null }
                Location = if (-not $SkipKeyVault) { $Location } else { $null }
                ServicePrincipalName = if ($application) { $ServicePrincipalName } else { $null }
                ApplicationId = $application.ApplicationId; ServicePrincipalId = $application.ServicePrincipalId
                ClientSecret = $secret.ClientSecret; SecretExpiration = $secret.SecretExpiration
                UseKeyVault = -not $SkipKeyVault; ConsentGranted = [bool]$application.ConsentGranted
            }
        }
    } catch {
        $exception = [System.InvalidOperationException]::new('Key Vault provisioning failed; service details suppressed. Resources, permissions or client credentials may already have been created. No rollback was attempted.')
        $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new($exception, 'KeyVaultProvisioningFailed', [System.Management.Automation.ErrorCategory]::InvalidOperation, $null))
    } finally {
        if ($secret) { $secret.ClientSecret = $null }
        $application = $null; $context = $null
    }

}
