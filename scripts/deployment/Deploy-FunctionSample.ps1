[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('powershell-keyvault-passkey-http', 'python-keyvault-passkey-http')]
    [string]$TemplateId,

    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter()]
    [string]$SubscriptionId = 'replace-with-your-subscription-id',

    [Parameter()]
    [string]$Location = 'westus2',

    [Parameter()]
    [string]$TenantId = 'replace-with-your-tenant-id',

    [Parameter(Mandatory)]
    [string]$BrowserExtensionClientId,

    [Parameter()]
    [string]$TokenClientId,

    [Parameter()]
    [string]$TokenRedirectUri = 'http://localhost',

    [Parameter()]
    [hashtable[]]$GraphDelegatedPermissions = @(
        @{ id = 'e1fe6dd8-ba31-4d61-89e7-88639da4683d'; value = 'User.Read' }
    ),

    [Parameter()]
    [string]$OktaDomain,

    [Parameter()]
    [ValidateSet('development', 'production')]
    [string]$DeploymentProfile = 'development',

    [Parameter()]
    [string]$EntraPortalOrigin = 'https://mysignins.microsoft.com',

    [Parameter()]
    [string]$OktaRedirectUri,

    [Parameter()]
    [string]$ExistingNatGatewayName,

    [Parameter()]
    [string]$ExistingNatGatewayResourceGroupName = 'rg-phish',

    [Parameter()]
    [string]$ExistingVirtualNetworkName,

    [Parameter()]
    [string]$ExistingVirtualNetworkResourceGroupName = 'rg-phish',

    [Parameter()]
    [string]$ExistingFunctionSubnetName,

    [Parameter()]
    [switch]$EnableVirtualNetworkIntegration,

    [Parameter()]
    [string]$EnvironmentName = 'sample',

    [Parameter()]
    [string]$CatalogTableName = 'PasskeyCredentials',

    [Parameter()]
    [string]$DeveloperPrincipalId,

    [Parameter()]
    [switch]$GrantCurrentUserDevelopmentAccess,

    [Parameter()]
    [switch]$EnableDevelopmentSecretExport,

    [Parameter()]
    [string]$AzConfigDir,

    [Parameter()]
    [switch]$SkipWhatIf,

    [Parameter()]
    [switch]$SkipCodeDeploy,

    [Parameter()]
    [ValidateRange(30, 1800)]
    [int]$PermissionPropagationTimeoutSeconds = 600,

    [Parameter()]
    [ValidateRange(5, 60)]
    [int]$PermissionPollIntervalSeconds = 15,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

function Wait-ForRoleAssignments {
    param(
        [Parameter(Mandatory)]
        [string[]]$RoleAssignmentIds,

        [Parameter(Mandatory)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory)]
        [int]$PollIntervalSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $missing = @()
        foreach ($roleAssignmentId in $RoleAssignmentIds) {
            $roleAssignmentMarker = '/providers/Microsoft.Authorization/roleAssignments/'
            $markerIndex = $roleAssignmentId.IndexOf($roleAssignmentMarker, [System.StringComparison]::OrdinalIgnoreCase)
            $assignmentName = if ($markerIndex -ge 0) { $roleAssignmentId.Substring($markerIndex + $roleAssignmentMarker.Length) } else { $roleAssignmentId }
            $assignmentScope = if ($markerIndex -ge 0) { $roleAssignmentId.Substring(0, $markerIndex) } else { $null }
            $assignmentJson = if ($assignmentScope) {
                & az role assignment list --scope $assignmentScope --query '[].{id:id,name:name}' --output json 2>$null
            } else {
                & az role assignment list --all --query '[].{id:id,name:name}' --output json 2>$null
            }
            $assignmentMatches = @()
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace(($assignmentJson -join ''))) {
                try {
                    $assignmentMatches = @($assignmentJson | ConvertFrom-Json | Where-Object {
                        ([string]$_.name -eq $assignmentName) -or ([string]$_.id -like "*/$assignmentName")
                    })
                } catch {
                    $assignmentMatches = @()
                }
            }
            if ($assignmentMatches.Count -eq 0) {
                $missing += $roleAssignmentId
            }
        }

        if ($missing.Count -eq 0) {
            return
        }

        if ((Get-Date) -ge $deadline) {
            throw "Timed out after $TimeoutSeconds seconds waiting for Azure RBAC role assignments to become visible: $($missing -join ', ')"
        }

        Write-Host "Waiting for $($missing.Count) Azure RBAC role assignment(s) to become visible; polling again in $PollIntervalSeconds seconds..."
        Start-Sleep -Seconds $PollIntervalSeconds
    } while ($true)
}

function Wait-ForCurrentUserStorageAccess {
    param(
        [Parameter(Mandatory)]
        [string]$StorageAccountName,

        [Parameter(Mandatory)]
        [string]$ContainerName,

        [Parameter(Mandatory)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory)]
        [int]$PollIntervalSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $containerResult = & az storage container show --account-name $StorageAccountName --name $ContainerName --auth-mode login --query name --output tsv 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace(($containerResult -join ''))) {
            return
        }

        if ((Get-Date) -ge $deadline) {
            throw "Timed out after $TimeoutSeconds seconds waiting for the signed-in developer to access storage account '$StorageAccountName'."
        }

        Write-Host "Waiting for developer storage RBAC to become usable; polling again in $PollIntervalSeconds seconds..."
        Start-Sleep -Seconds $PollIntervalSeconds
    } while ($true)
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI was not found. Install Azure CLI before using this deployment helper.'
}

if ($CatalogTableName -notmatch '^[A-Za-z][A-Za-z0-9]{2,62}$') {
    throw 'CatalogTableName must be 3-63 alphanumeric characters and start with a letter.'
}

$parsedBrowserExtensionClientId = [guid]::Empty
if (-not [guid]::TryParse($BrowserExtensionClientId, [ref]$parsedBrowserExtensionClientId)) {
    throw 'BrowserExtensionClientId must be the GUID client ID produced by New-BrowserFunctionAppRegistration.ps1.'
}

if ($TemplateId -in @('powershell-keyvault-passkey-http', 'python-keyvault-passkey-http')) {
    if (-not [string]::IsNullOrWhiteSpace($TokenClientId)) {
        $parsedTokenClientId = [guid]::Empty
        if (-not [guid]::TryParse($TokenClientId, [ref]$parsedTokenClientId)) {
            throw 'TokenClientId must be a GUID for an existing public-client application.'
        }
    }
    $parsedTokenRedirectUri = $null
    if (-not [uri]::TryCreate($TokenRedirectUri, [System.UriKind]::Absolute, [ref]$parsedTokenRedirectUri) -or
        $parsedTokenRedirectUri.Scheme -notin @('http', 'https') -or $parsedTokenRedirectUri.Query -or $parsedTokenRedirectUri.Fragment) {
        throw 'TokenRedirectUri must be an absolute HTTP or HTTPS URI without a query string or fragment.'
    }
    if ($GraphDelegatedPermissions.Count -eq 0) {
        throw 'At least one GraphDelegatedPermissions entry is required.'
    }
    foreach ($permission in $GraphDelegatedPermissions) {
        $permissionId = [guid]::Empty
        if (-not [guid]::TryParse([string]$permission.id, [ref]$permissionId) -or [string]$permission.value -notmatch '^[A-Za-z][A-Za-z0-9.]+$') {
            throw 'Each GraphDelegatedPermissions entry requires a GUID id and a scope value containing letters, numbers, and periods.'
        }
    }
}

if ($DeploymentProfile -eq 'production' -and ($GrantCurrentUserDevelopmentAccess -or -not [string]::IsNullOrWhiteSpace($DeveloperPrincipalId))) {
    throw 'Direct developer RBAC cannot be granted with DeploymentProfile=production. Use a development deployment or broker access.'
}
if ($DeploymentProfile -eq 'production' -and $EnableDevelopmentSecretExport) {
    throw 'Development secret export cannot be enabled with DeploymentProfile=production.'
}

if ([string]::IsNullOrWhiteSpace($AzConfigDir)) {
    $tempRoot = if (-not [string]::IsNullOrWhiteSpace($env:TEMP)) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
    $AzConfigDir = Join-Path $tempRoot 'azcfg-research-passkeys'
}
New-Item -ItemType Directory -Path $AzConfigDir -Force | Out-Null
$env:AZURE_CONFIG_DIR = $AzConfigDir

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$sampleMap = @{
    'powershell-keyvault-passkey-http' = @{
        SampleRoot  = Join-Path $repoRoot 'function-app\powershell\keyvault-passkey-http'
        SyncScript  = Join-Path $repoRoot 'function-app\powershell\keyvault-passkey-http\scripts\Sync-PasskeyAssets.ps1'
        SourceRoot  = Join-Path $repoRoot 'function-app\powershell\keyvault-passkey-http\src'
        BuildRemote = $false
    }
    'python-keyvault-passkey-http' = @{
        SampleRoot  = Join-Path $repoRoot 'function-app\python\keyvault-passkey-http'
        SyncScript  = Join-Path $repoRoot 'function-app\python\keyvault-passkey-http\scripts\Sync-PasskeyLibrary.ps1'
        SourceRoot  = Join-Path $repoRoot 'function-app\python\keyvault-passkey-http\src'
        BuildRemote = $true
    }
}

$sample = $sampleMap[$TemplateId]
$sampleRoot = [string]$sample.SampleRoot
$syncScript = [string]$sample.SyncScript
$sourceRoot = [string]$sample.SourceRoot
$infraPath = Join-Path $sampleRoot 'infra\main.bicep'

if ($TemplateId -in @('powershell-keyvault-passkey-http', 'python-keyvault-passkey-http') -and [string]::IsNullOrWhiteSpace($TokenClientId)) {
    Write-Host 'TokenClientId was not supplied; deployment will use the built-in Azure CLI public client for token acquisition.'
}

if (-not (Test-Path -LiteralPath $sampleRoot)) {
    throw "Sample root not found: $sampleRoot"
}
if (-not (Test-Path -LiteralPath $infraPath)) {
    throw "Bicep template not found: $infraPath"
}
if (-not (Test-Path -LiteralPath $sourceRoot)) {
    throw "Function source root not found: $sourceRoot"
}

if (Test-Path -LiteralPath $syncScript) {
    & $syncScript
}

& az account set --subscription $SubscriptionId | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to select subscription $SubscriptionId."
}

if (-not [string]::IsNullOrWhiteSpace($ExistingNatGatewayName)) {
    if ([string]::IsNullOrWhiteSpace($ExistingVirtualNetworkName) -or [string]::IsNullOrWhiteSpace($ExistingFunctionSubnetName)) {
        throw 'An existing NAT Gateway cannot be shared with a newly-created VNet. Pass ExistingVirtualNetworkName and ExistingFunctionSubnetName for a dedicated subnet in the NAT Gateway''s VNet.'
    }
    $natLocation = [string](& az network nat gateway show --resource-group $ExistingNatGatewayResourceGroupName --name $ExistingNatGatewayName --query location --output tsv)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($natLocation)) {
        throw "Existing NAT Gateway '$ExistingNatGatewayName' was not found in resource group '$ExistingNatGatewayResourceGroupName' for subscription '$SubscriptionId'."
    }
    if ($natLocation.Trim().ToLowerInvariant() -ne $Location.Trim().ToLowerInvariant()) {
        throw "Existing NAT Gateway location '$natLocation' does not match deployment location '$Location'."
    }
}

$hasExistingVirtualNetwork = -not [string]::IsNullOrWhiteSpace($ExistingVirtualNetworkName)
$hasExistingFunctionSubnet = -not [string]::IsNullOrWhiteSpace($ExistingFunctionSubnetName)
if ($hasExistingVirtualNetwork -ne $hasExistingFunctionSubnet) {
    throw 'ExistingVirtualNetworkName and ExistingFunctionSubnetName must be supplied together.'
}
if ($hasExistingVirtualNetwork) {
    $existingVirtualNetworkLocation = [string](& az network vnet show --resource-group $ExistingVirtualNetworkResourceGroupName --name $ExistingVirtualNetworkName --query location --output tsv)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($existingVirtualNetworkLocation)) {
        throw "Existing VNet '$ExistingVirtualNetworkName' was not found in resource group '$ExistingVirtualNetworkResourceGroupName'."
    }
    if ($existingVirtualNetworkLocation.Trim().ToLowerInvariant() -ne $Location.Trim().ToLowerInvariant()) {
        throw "Existing VNet location '$existingVirtualNetworkLocation' does not match deployment location '$Location'."
    }
    $existingFunctionSubnetResourceId = [string](& az network vnet subnet show --resource-group $ExistingVirtualNetworkResourceGroupName --vnet-name $ExistingVirtualNetworkName --name $ExistingFunctionSubnetName --query id --output tsv)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($existingFunctionSubnetResourceId)) {
        throw "Existing subnet '$ExistingFunctionSubnetName' was not found in VNet '$ExistingVirtualNetworkName'."
    }
    $subnetDetailsJson = & az network vnet subnet show --resource-group $ExistingVirtualNetworkResourceGroupName --vnet-name $ExistingVirtualNetworkName --name $ExistingFunctionSubnetName --query "{delegations:delegations[].serviceName,serviceEndpoints:serviceEndpoints[].service,privateEndpoints:privateEndpoints[].id,ipConfigurations:ipConfigurations[].id}" --output json
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to inspect existing subnet '$ExistingFunctionSubnetName'."
    }
    $subnetDetails = $subnetDetailsJson | ConvertFrom-Json
    $delegations = @($subnetDetails.delegations | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $serviceEndpoints = @($subnetDetails.serviceEndpoints | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $privateEndpoints = @($subnetDetails.privateEndpoints | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $ipConfigurations = @($subnetDetails.ipConfigurations | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($delegations.Count -gt 0 -and -not ($delegations -contains 'Microsoft.App/environments')) {
        throw "Existing subnet '$ExistingFunctionSubnetName' is delegated to another service and is not suitable for Flex Consumption."
    }
    if ($serviceEndpoints.Count -gt 0 -or $privateEndpoints.Count -gt 0 -or $ipConfigurations.Count -gt 0) {
        throw "Existing subnet '$ExistingFunctionSubnetName' must be a dedicated, otherwise-empty Flex Consumption subnet without service/private endpoints or existing IP configurations."
    }
    if (-not [string]::IsNullOrWhiteSpace($ExistingNatGatewayName)) {
        $natSubnetIds = @(& az network nat gateway show --resource-group $ExistingNatGatewayResourceGroupName --name $ExistingNatGatewayName --query 'subnets[].id' --output tsv)
        if ($LASTEXITCODE -ne 0 -or -not ($natSubnetIds | Where-Object { ([string]$_).Trim() -eq $existingFunctionSubnetResourceId.Trim() })) {
            throw "Subnet '$ExistingFunctionSubnetName' is not attached to NAT Gateway '$ExistingNatGatewayName'. Select the NAT-attached, dedicated Flex subnet or attach the NAT to it first."
        }
    }
}

if ($GrantCurrentUserDevelopmentAccess -and [string]::IsNullOrWhiteSpace($DeveloperPrincipalId)) {
    $DeveloperPrincipalId = [string](& az ad signed-in-user show --query id --output tsv)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($DeveloperPrincipalId)) {
        throw 'Could not resolve the signed-in user object ID for direct development access. Pass -DeveloperPrincipalId explicitly.'
    }
    $DeveloperPrincipalId = $DeveloperPrincipalId.Trim()
}

& az group create --name $ResourceGroupName --location $Location --output none | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create or select resource group $ResourceGroupName."
}

$parameterArgs = @(
    '--parameters', "location=$Location",
    '--parameters', "tenantId=$TenantId",
    '--parameters', "browserExtensionClientId=$BrowserExtensionClientId",
    '--parameters', "environmentName=$EnvironmentName",
    '--parameters', "catalogTableName=$CatalogTableName",
    '--parameters', "deploymentProfile=$DeploymentProfile",
    '--parameters', "entraPortalOrigin=$EntraPortalOrigin",
    '--parameters', "existingVirtualNetworkResourceGroupName=$ExistingVirtualNetworkResourceGroupName"
)
if ($EnableVirtualNetworkIntegration) {
    $parameterArgs += @('--parameters', 'enableVirtualNetworkIntegration=true')
}
if ($EnableDevelopmentSecretExport) {
    $parameterArgs += @('--parameters', 'enableDevelopmentSecretExport=true')
}
if (-not [string]::IsNullOrWhiteSpace($OktaDomain)) {
    $parameterArgs += @('--parameters', "oktaDomain=$OktaDomain")
}
if (-not [string]::IsNullOrWhiteSpace($OktaRedirectUri)) {
    $parameterArgs += @('--parameters', "oktaRedirectUri=$OktaRedirectUri")
}
if (-not [string]::IsNullOrWhiteSpace($ExistingVirtualNetworkName)) {
    $parameterArgs += @('--parameters', "existingVirtualNetworkName=$ExistingVirtualNetworkName")
    $parameterArgs += @('--parameters', "existingFunctionSubnetName=$ExistingFunctionSubnetName")
}
if (-not [string]::IsNullOrWhiteSpace($DeveloperPrincipalId)) {
    $parameterArgs += @('--parameters', "developerPrincipalId=$DeveloperPrincipalId")
}
if ($TemplateId -in @('powershell-keyvault-passkey-http', 'python-keyvault-passkey-http')) {
    $graphPermissionsJson = ConvertTo-Json -InputObject $GraphDelegatedPermissions -Depth 5 -Compress
    $parameterArgs += @('--parameters', "tokenClientId=$TokenClientId")
    $parameterArgs += @('--parameters', "tokenRedirectUri=$TokenRedirectUri")
    $parameterArgs += @('--parameters', "graphDelegatedPermissions=$graphPermissionsJson")
}

if (-not $SkipWhatIf) {
    & az deployment group what-if `
        --resource-group $ResourceGroupName `
        --template-file $infraPath `
        @parameterArgs
    if ($LASTEXITCODE -ne 0) {
        throw 'Bicep what-if failed.'
    }
}

$deploymentJson = & az deployment group create `
    --resource-group $ResourceGroupName `
    --template-file $infraPath `
    @parameterArgs `
    --query properties.outputs `
    --output json
if ($LASTEXITCODE -ne 0) {
    throw 'Bicep deployment failed.'
}

$deploymentOutputs = $deploymentJson | ConvertFrom-Json
$functionAppName = [string]$deploymentOutputs.functionAppName.value
$functionAppDefaultHostname = [string]$deploymentOutputs.functionAppDefaultHostname.value
$keyVaultName = [string]$deploymentOutputs.keyVaultName.value
$keyVaultResourceId = [string]$deploymentOutputs.keyVaultResourceId.value
$managedIdentityClientId = [string]$deploymentOutputs.managedIdentityClientId.value
$managedIdentityPrincipalId = [string]$deploymentOutputs.managedIdentityPrincipalId.value
$networkIntegrationEnabled = [bool]$deploymentOutputs.networkIntegrationEnabled.value
$existingVirtualNetworkResourceId = [string]$deploymentOutputs.existingVirtualNetworkResourceId.value
$existingFunctionSubnetResourceId = [string]$deploymentOutputs.existingFunctionSubnetResourceId.value
$storageAccountName = [string]$deploymentOutputs.storageAccountName.value
$storageAccountResourceId = [string]$deploymentOutputs.storageAccountResourceId.value
$storageTableServiceUri = [string]$deploymentOutputs.storageTableServiceUri.value
$deployedCatalogTableName = [string]$deploymentOutputs.catalogTableName.value
$catalogTableResourceId = [string]$deploymentOutputs.catalogTableResourceId.value
$captureTableResourceId = [string]$deploymentOutputs.captureTableResourceId.value
$captureContainerResourceId = [string]$deploymentOutputs.captureContainerResourceId.value
$deploymentContainerResourceId = [string]$deploymentOutputs.deploymentContainerResourceId.value
$registrationStatusContainerResourceId = [string]$deploymentOutputs.registrationStatusContainerResourceId.value
$registrationQueueResourceId = [string]$deploymentOutputs.registrationQueueResourceId.value
$oktaRegistrationQueueResourceId = [string]$deploymentOutputs.oktaRegistrationQueueResourceId.value
$managedIdentityStorageBlobRoleAssignmentId = [string]$deploymentOutputs.managedIdentityStorageBlobRoleAssignmentId.value
$managedIdentityStorageQueueRoleAssignmentId = [string]$deploymentOutputs.managedIdentityStorageQueueRoleAssignmentId.value
$managedIdentityStorageTableRoleAssignmentId = [string]$deploymentOutputs.managedIdentityStorageTableRoleAssignmentId.value
$managedIdentityKeyVaultRoleAssignmentId = [string]$deploymentOutputs.managedIdentityKeyVaultRoleAssignmentId.value
$deployedTokenClientId = if ($deploymentOutputs.tokenClientId) { [string]$deploymentOutputs.tokenClientId.value } else { '' }
$deployedTokenRedirectUri = if ($deploymentOutputs.tokenRedirectUri) { [string]$deploymentOutputs.tokenRedirectUri.value } else { '' }
$deployedGraphAllowedScopes = if ($deploymentOutputs.graphAllowedScopes) { @($deploymentOutputs.graphAllowedScopes.value) } else { @() }

$requiredOutputs = @{
    functionAppName = $functionAppName
    keyVaultName = $keyVaultName
    keyVaultResourceId = $keyVaultResourceId
    managedIdentityClientId = $managedIdentityClientId
    managedIdentityPrincipalId = $managedIdentityPrincipalId
    networkIntegrationEnabled = $networkIntegrationEnabled
    storageAccountName = $storageAccountName
    storageAccountResourceId = $storageAccountResourceId
    storageTableServiceUri = $storageTableServiceUri
    catalogTableName = $deployedCatalogTableName
    catalogTableResourceId = $catalogTableResourceId
    captureTableResourceId = $captureTableResourceId
    captureContainerResourceId = $captureContainerResourceId
    deploymentContainerResourceId = $deploymentContainerResourceId
    registrationStatusContainerResourceId = $registrationStatusContainerResourceId
    registrationQueueResourceId = $registrationQueueResourceId
    oktaRegistrationQueueResourceId = $oktaRegistrationQueueResourceId
    managedIdentityStorageBlobRoleAssignmentId = $managedIdentityStorageBlobRoleAssignmentId
    managedIdentityStorageQueueRoleAssignmentId = $managedIdentityStorageQueueRoleAssignmentId
    managedIdentityStorageTableRoleAssignmentId = $managedIdentityStorageTableRoleAssignmentId
    managedIdentityKeyVaultRoleAssignmentId = $managedIdentityKeyVaultRoleAssignmentId
}
foreach ($entry in $requiredOutputs.GetEnumerator()) {
    if ([string]::IsNullOrWhiteSpace([string]$entry.Value)) {
        throw "Bicep deployment did not return required output '$($entry.Key)'."
    }
}
if ($hasExistingVirtualNetwork -and ([string]::IsNullOrWhiteSpace($existingVirtualNetworkResourceId) -or [string]::IsNullOrWhiteSpace($existingFunctionSubnetResourceId))) {
    throw 'An existing VNet/subnet was requested, but the deployment did not return the existing network resource IDs.'
}

Wait-ForRoleAssignments -RoleAssignmentIds @(
    $managedIdentityStorageBlobRoleAssignmentId,
    $managedIdentityStorageQueueRoleAssignmentId,
    $managedIdentityStorageTableRoleAssignmentId,
    $managedIdentityKeyVaultRoleAssignmentId
) -TimeoutSeconds $PermissionPropagationTimeoutSeconds -PollIntervalSeconds $PermissionPollIntervalSeconds

$requiredResourceIds = @(
    $catalogTableResourceId,
    $captureTableResourceId,
    $captureContainerResourceId,
    $deploymentContainerResourceId,
    $registrationStatusContainerResourceId,
    $registrationQueueResourceId,
    $oktaRegistrationQueueResourceId
)
foreach ($resourceId in $requiredResourceIds) {
    & az resource show --ids $resourceId --output none | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Required storage child resource was not found after deployment: $resourceId"
    }
}

$appSettingsJson = & az functionapp config appsettings list `
    --name $functionAppName `
    --resource-group $ResourceGroupName `
    --output json
if ($LASTEXITCODE -ne 0) {
    throw "Failed to verify app settings for $functionAppName."
}
$appSettings = @{}
foreach ($setting in @($appSettingsJson | ConvertFrom-Json)) {
    $appSettings[[string]$setting.name] = [string]$setting.value
}
$expectedSettings = @{
    'AzureWebJobsStorage__tableServiceUri' = $storageTableServiceUri
    'AzureWebJobsStorage__credential' = 'managedidentity'
    'AzureWebJobsStorage__clientId' = $managedIdentityClientId
    'PASSKEY_KEYVAULT_NAME' = $keyVaultName
    'PASSKEY_MANAGED_IDENTITY_CLIENT_ID' = $managedIdentityClientId
    'PASSKEY_CATALOG_TABLE_NAME' = $deployedCatalogTableName
    'PASSKEY_CAPTURE_TABLE_NAME' = 'PasskeyCaptureContexts'
    'PASSKEY_CAPTURE_CONTAINER_NAME' = 'passkey-capture-context'
    'PASSKEY_ENABLE_DEV_SECRET_EXPORT' = $(if ($EnableDevelopmentSecretExport) { 'true' } else { 'false' })
    'PASSKEY_DEPLOYMENT_PROFILE' = $DeploymentProfile
    'PASSKEY_ENTRA_PORTAL_ORIGIN' = $EntraPortalOrigin
    'PASSKEY_ALLOW_LOCAL_CREDENTIALS' = 'false'
}
if ($TemplateId -in @('powershell-keyvault-passkey-http', 'python-keyvault-passkey-http')) {
    $expectedSettings['PASSKEY_TOKEN_CLIENT_ID'] = $deployedTokenClientId
    $expectedSettings['PASSKEY_TOKEN_REDIRECT_URI'] = $deployedTokenRedirectUri
    $expectedSettings['PASSKEY_GRAPH_ALLOWED_SCOPES'] = ($deployedGraphAllowedScopes -join ',')
}
foreach ($entry in $expectedSettings.GetEnumerator()) {
    if ($appSettings[[string]$entry.Key] -ne [string]$entry.Value) {
        throw "Function app setting '$($entry.Key)' was not configured with the expected deployed value."
    }
}

if ($GrantCurrentUserDevelopmentAccess) {
    Wait-ForCurrentUserStorageAccess -StorageAccountName $storageAccountName -ContainerName (($deploymentContainerResourceId -split '/')[-1]) -TimeoutSeconds $PermissionPropagationTimeoutSeconds -PollIntervalSeconds $PermissionPollIntervalSeconds
}

$tempRoot = if (-not [string]::IsNullOrWhiteSpace($env:TEMP)) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
$zipPath = Join-Path $tempRoot "$TemplateId-$(Get-Date -Format 'yyyyMMdd-HHmmss').zip"
try {
    if (-not $SkipCodeDeploy) {
        Compress-Archive -Path (Join-Path $sourceRoot '*') -DestinationPath $zipPath -Force

        $deployArgs = @(
            'functionapp', 'deployment', 'source', 'config-zip',
            '--src', $zipPath,
            '--name', $functionAppName,
            '--resource-group', $ResourceGroupName
        )
        if ([bool]$sample.BuildRemote) {
            $deployArgs += @('--build-remote', 'true')
        }

        & az @deployArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Function code deployment failed for $functionAppName."
        }
    }
} finally {
    if (Test-Path -LiteralPath $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
    }
}

$result = [PSCustomObject]@{
    templateId                = $TemplateId
    resourceGroupName         = $ResourceGroupName
    subscriptionId            = $SubscriptionId
    location                  = $Location
    environmentName           = $EnvironmentName
    catalogTableName          = $deployedCatalogTableName
    catalogTableResourceId    = $catalogTableResourceId
    captureTableResourceId    = $captureTableResourceId
    captureContainerResourceId = $captureContainerResourceId
    deploymentContainerResourceId = $deploymentContainerResourceId
    registrationStatusContainerResourceId = $registrationStatusContainerResourceId
    registrationQueueResourceId = $registrationQueueResourceId
    oktaRegistrationQueueResourceId = $oktaRegistrationQueueResourceId
    storageAccountName        = $storageAccountName
    storageAccountResourceId  = $storageAccountResourceId
    storageTableServiceUri    = $storageTableServiceUri
    oktaDomain                = $OktaDomain
    developerPrincipalId      = $DeveloperPrincipalId
    existingNatGatewayName    = $ExistingNatGatewayName
    existingNatGatewayResourceGroupName = $ExistingNatGatewayResourceGroupName
    existingVirtualNetworkName = $ExistingVirtualNetworkName
    existingVirtualNetworkResourceGroupName = $ExistingVirtualNetworkResourceGroupName
    existingVirtualNetworkResourceId = $existingVirtualNetworkResourceId
    existingFunctionSubnetName = $ExistingFunctionSubnetName
    existingFunctionSubnetResourceId = $existingFunctionSubnetResourceId
    networkIntegrationEnabled = $networkIntegrationEnabled
    developmentSecretExportEnabled = [bool]$EnableDevelopmentSecretExport
    tokenClientId             = $deployedTokenClientId
    tokenRedirectUri          = $deployedTokenRedirectUri
    graphAllowedScopes        = $deployedGraphAllowedScopes
    deploymentProfile         = $DeploymentProfile
    entraPortalOrigin         = $EntraPortalOrigin
    azConfigDir               = $AzConfigDir
    functionAppName           = $functionAppName
    functionAppDefaultHostname = $functionAppDefaultHostname
    keyVaultName              = $keyVaultName
    keyVaultResourceId        = $keyVaultResourceId
    managedIdentityClientId   = $managedIdentityClientId
    managedIdentityPrincipalId = $managedIdentityPrincipalId
    managedIdentityStorageBlobRoleAssignmentId = $managedIdentityStorageBlobRoleAssignmentId
    managedIdentityStorageQueueRoleAssignmentId = $managedIdentityStorageQueueRoleAssignmentId
    managedIdentityStorageTableRoleAssignmentId = $managedIdentityStorageTableRoleAssignmentId
    managedIdentityKeyVaultRoleAssignmentId = $managedIdentityKeyVaultRoleAssignmentId
    infrastructureValidated   = $true
    codeDeployed              = -not $SkipCodeDeploy
}

if ($PassThru) {
    Write-Output $result
} else {
    $result | ConvertTo-Json -Compress
}
