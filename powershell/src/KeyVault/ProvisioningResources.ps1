function Initialize-EntraKeyVaultProvisioningResourceGroup {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Location)
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$([uri]::EscapeDataString($ResourceGroupName))?api-version=2021-04-01"
    try { $null = Invoke-EntraKeyVaultProvisioningArmRequest -Method GET -Uri $uri }
    catch {
        if (-not (Test-EntraKeyVaultProvisioningNotFound -ErrorRecord $_)) { throw }
        $null = Invoke-EntraKeyVaultProvisioningArmRequest -Method PUT -Uri $uri -Payload (@{ location = $Location } | ConvertTo-Json)
    }
}

function Initialize-EntraKeyVaultProvisioningVault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$Location, [ValidateSet('standard', 'premium')][string]$Sku = 'standard',
        [bool]$EnablePurgeProtection = $true
    )
    $scope = "/subscriptions/$SubscriptionId/resourceGroups/$([uri]::EscapeDataString($ResourceGroupName))/providers/Microsoft.KeyVault/vaults/$VaultName"
    $uri = "https://management.azure.com$scope`?api-version=2023-02-01"
    try {
        $response = Invoke-EntraKeyVaultProvisioningArmRequest -Method GET -Uri $uri
        $vault = $response.Content | ConvertFrom-Json -ErrorAction Stop
        if ($vault.properties.tenantId -and $vault.properties.tenantId -ne $TenantId) { throw 'Existing Key Vault belongs to a different tenant.' }
        if (-not $vault.properties.enableRbacAuthorization) { throw 'Existing Key Vault must use RBAC authorization.' }
        if (-not $vault.properties.enablePurgeProtection) { Write-Warning 'Existing Key Vault does not have purge protection enabled.' }
    } catch {
        if (-not (Test-EntraKeyVaultProvisioningNotFound -ErrorRecord $_)) { throw }
        $nameUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.KeyVault/checkNameAvailability?api-version=2024-11-01"
        $body = @{ name = $VaultName; type = 'Microsoft.KeyVault/vaults' } | ConvertTo-Json
        $response = Invoke-EntraKeyVaultProvisioningArmRequest -Method POST -Uri $nameUri -Payload $body
        $available = $response.Content | ConvertFrom-Json -ErrorAction Stop
        if ($available.nameAvailable -ne $true) { throw 'Key Vault name is not available.' }
        $body = @{
            location = $Location
            properties = @{
                sku = @{ family = 'A'; name = $Sku.ToLowerInvariant() }; tenantId = $TenantId
                enableRbacAuthorization = $true; softDeleteRetentionInDays = 90; enablePurgeProtection = $EnablePurgeProtection
            }
        } | ConvertTo-Json -Depth 10
        $null = Invoke-EntraKeyVaultProvisioningArmRequest -Method PUT -Uri $uri -Payload $body
        for ($attempt = 1; $attempt -le 12; $attempt++) {
            Start-Sleep -Seconds 5
            try { $null = Invoke-EntraKeyVaultProvisioningArmRequest -Method GET -Uri $uri; break }
            catch { if ($attempt -eq 12) { Write-Warning 'Key Vault readiness could not be confirmed; allow time for provisioning.' } }
        }
    }
    $scope
}

function Initialize-EntraKeyVaultProvisioningRole {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$VaultScope, [Parameter(Mandatory)][string]$ServicePrincipalId)
    $filter = [uri]::EscapeDataString("roleName eq 'Key Vault Crypto Officer'")
    $definitionUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions?`$filter=$filter&api-version=2022-04-01"
    $definitions = Invoke-EntraKeyVaultProvisioningArmRequest -Method GET -Uri $definitionUri
    $roles = @(($definitions.Content | ConvertFrom-Json -ErrorAction Stop).value)
    if ($roles.Count -ne 1 -or -not $roles[0].id) { throw 'Key Vault Crypto Officer role definition was missing or ambiguous.' }
    $roleId = [string]$roles[0].id
    $uri = "https://management.azure.com$VaultScope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    $response = Invoke-EntraKeyVaultProvisioningArmRequest -Method GET -Uri $uri
    $roles = ($response.Content | ConvertFrom-Json -ErrorAction Stop).value
    $existing = $roles | Where-Object { $_.properties.principalId -eq $ServicePrincipalId -and $_.properties.roleDefinitionId -eq $roleId }
    if ($existing) { return }
    $assignment = [guid]::NewGuid().ToString()
    $createUri = "https://management.azure.com$VaultScope/providers/Microsoft.Authorization/roleAssignments/$assignment`?api-version=2022-04-01"
    $body = @{ properties = @{ roleDefinitionId = $roleId; principalId = $ServicePrincipalId; principalType = 'ServicePrincipal' } } | ConvertTo-Json
    $null = Invoke-EntraKeyVaultProvisioningArmRequest -Method PUT -Uri $createUri -Payload $body
    for ($attempt = 1; $attempt -le 60; $attempt++) {
        Start-Sleep -Seconds 5
        try {
            $response = Invoke-EntraKeyVaultProvisioningArmRequest -Method GET -Uri $uri
            $roles = ($response.Content | ConvertFrom-Json -ErrorAction Stop).value
            if ($roles | Where-Object { $_.properties.principalId -eq $ServicePrincipalId -and $_.properties.roleDefinitionId -eq $roleId }) { return }
        } catch { Write-Verbose 'Waiting for Key Vault role assignment propagation.' }
    }
    Write-Warning 'Key Vault role assignment propagation could not be confirmed.'
}
