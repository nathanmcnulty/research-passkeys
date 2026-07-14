@description('Primary region for all resources and the Flex Consumption Function App.')
param location string = 'westus2'

@description('Tenant ID used by the passkey registration scripts.')
param tenantId string = '847b5907-ca15-40f4-b171-eb18619dbfab'

@description('Optional Okta organization domain used as the default by the Okta Function routes.')
param oktaDomain string = ''

@description('Server-controlled Entra portal origin. Requests cannot override this value.')
param entraPortalOrigin string = 'https://mysignins.microsoft.com'

@description('Optional server-controlled Okta OAuth redirect URI. When empty, the configured Okta origin callback is used.')
param oktaRedirectUri string = ''

@description('Deployment security profile. Production restricts Storage and Key Vault to the Function integration subnet.')
@allowed([
  'development'
  'production'
])
param deploymentProfile string = 'development'

@description('Opt-in VNet integration for development validation. This remains false for ordinary development deployments.')
param enableVirtualNetworkIntegration bool = false

@description('Address space used by the optional Function virtual network.')
param virtualNetworkAddressPrefix string = '10.43.0.0/16'

@description('Subnet used for Function regional VNet integration.')
param functionSubnetAddressPrefix string = '10.43.0.0/24'

@description('Optional existing VNet used for development validation. The VNet must be in the same subscription and region as this Function App.')
param existingVirtualNetworkName string = ''

@description('Resource group containing the existing VNet.')
param existingVirtualNetworkResourceGroupName string = 'rg-phish'

@description('Dedicated Flex Consumption integration subnet in the existing VNet.')
param existingFunctionSubnetName string = ''

@description('Short environment name used in resource naming.')
param environmentName string = 'sample'

@description('Optional tags applied to all resources.')
param tags object = {}

@description('PowerShell runtime used by the Function App.')
@allowed([
  'powerShell'
])
param functionAppRuntime string = 'powerShell'

@description('PowerShell runtime version used by the Function App.')
@allowed([
  '7.4'
])
param functionAppRuntimeVersion string = '7.4'

@description('Maximum scale-out instance count for the Function App.')
@minValue(40)
@maxValue(1000)
param maximumInstanceCount int = 100

@description('Memory size for Flex Consumption instances.')
@allowed([
  2048
  4096
])
param instanceMemoryMB int = 2048

@description('Key Vault SKU for the sample. Standard is sufficient for the current software-backed passkey flow.')
@allowed([
  'standard'
  'premium'
])
param keyVaultSkuName string = 'standard'

@description('Azure Table name used for canonical passkey metadata.')
@minLength(3)
@maxLength(63)
param catalogTableName string = 'PasskeyCredentials'

@description('Azure Table name used for capture provenance metadata.')
param captureTableName string = 'PasskeyCaptureContexts'

@description('Enables secret export endpoints. This may only be true in the development profile.')
param enableDevelopmentSecretExport bool = false

@description('Optional Entra object ID granted direct development access to Key Vault and Function storage data. Leave empty for broker-only access.')
param developerPrincipalId string = ''

var resourceToken = toLower(uniqueString(subscription().id, resourceGroup().id, environmentName))
var functionAppName = 'func-kvpk-${take(resourceToken, 8)}'
var keyVaultName = 'kvpk${take(resourceToken, 20)}'
var storageAccountName = 'st${take(resourceToken, 22)}'
var appInsightsName = 'appi-kvpk-${take(resourceToken, 8)}'
var logAnalyticsName = 'log-kvpk-${take(resourceToken, 8)}'
var planName = 'plan-kvpk-${take(resourceToken, 8)}'
var userAssignedIdentityName = 'uai-kvpk-${take(resourceToken, 8)}'
var deploymentStorageContainerName = 'app-package-${take(resourceToken, 12)}'
var registrationStatusContainerName = 'passkey-registration-status'
var registrationQueueName = 'passkey-registration'
var oktaRegistrationQueueName = 'okta-passkey-registration'
var captureContainerName = 'passkey-capture-context'

var storageBlobDataOwnerRoleId = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
var storageBlobDataContributorId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var storageQueueDataContributorId = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
var storageTableDataContributorId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
var monitoringMetricsPublisherId = '3913510d-42f4-4e42-8a64-420c390055eb'
var productionProfile = deploymentProfile == 'production'
var useExistingVirtualNetwork = !empty(existingVirtualNetworkName) && !empty(existingFunctionSubnetName)
var networkIntegrationEnabled = productionProfile || enableVirtualNetworkIntegration || useExistingVirtualNetwork
var passkeyKeyOperatorRoleName = 'Passkey Key Operator ${take(resourceToken, 8)}'

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsName
  location: location
  tags: tags
  properties: any({
    retentionInDays: 30
    features: {
      searchVersion: 1
    }
    sku: {
      name: 'PerGB2018'
    }
  })
}

resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  tags: tags
  properties: {
    Application_Type: 'web'
    DisableLocalAuth: true
    WorkspaceResourceId: logAnalytics.id
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  tags: tags
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    minimumTlsVersion: 'TLS1_2'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: productionProfile ? 'Deny' : 'Allow'
      virtualNetworkRules: productionProfile ? [
        {
          id: functionSubnetResourceId
          action: 'Allow'
        }
      ] : []
    }
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
  }
  resource blobServices 'blobServices' = {
    name: 'default'
    resource deploymentContainer 'containers' = {
      name: deploymentStorageContainerName
      properties: {
        publicAccess: 'None'
      }
    }
    resource registrationStatusContainer 'containers' = {
      name: registrationStatusContainerName
      properties: {
        publicAccess: 'None'
      }
    }
    resource captureContainer 'containers' = {
      name: captureContainerName
      properties: {
        publicAccess: 'None'
      }
    }
  }
  resource queueServices 'queueServices' = {
    name: 'default'
    resource registrationQueue 'queues' = {
      name: registrationQueueName
    }
    resource oktaRegistrationQueue 'queues' = {
      name: oktaRegistrationQueueName
    }
  }
  resource tableServices 'tableServices' = {
    name: 'default'
    resource catalogTable 'tables' = {
      name: catalogTableName
    }
    resource captureTable 'tables' = {
      name: captureTableName
    }
  }
  resource managementPolicy 'managementPolicies' = {
    name: 'default'
    properties: {
      policy: {
        rules: [
          {
            enabled: true
            name: 'delete-expired-passkey-captures'
            type: 'Lifecycle'
            definition: {
              actions: {
                baseBlob: {
                  delete: {
                    daysAfterCreationGreaterThan: 1
                  }
                }
              }
              filters: {
                blobTypes: ['blockBlob']
                prefixMatch: ['${captureContainerName}/']
              }
            }
          }
        ]
      }
    }
  }
}

resource userAssignedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: userAssignedIdentityName
  location: location
  tags: tags
}

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2024-05-01' = if (networkIntegrationEnabled && !useExistingVirtualNetwork) {
  name: 'vnet-kvpk-${take(resourceToken, 8)}'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [virtualNetworkAddressPrefix]
    }
    subnets: [
      {
        name: 'snet-functions'
        properties: {
          addressPrefix: functionSubnetAddressPrefix
          delegations: [
            {
              name: 'function-flex-delegation'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
          serviceEndpoints: [
            { service: 'Microsoft.Storage' }
            { service: 'Microsoft.KeyVault' }
          ]
        }
      }
    ]
  }
}

resource existingVirtualNetwork 'Microsoft.Network/virtualNetworks@2024-05-01' existing = if (useExistingVirtualNetwork) {
  name: existingVirtualNetworkName
  scope: resourceGroup(existingVirtualNetworkResourceGroupName)
}

resource existingFunctionSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = if (useExistingVirtualNetwork) {
  parent: existingVirtualNetwork
  name: existingFunctionSubnetName
}

resource functionSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = if (networkIntegrationEnabled && !useExistingVirtualNetwork) {
  parent: virtualNetwork
  name: 'snet-functions'
}

var functionSubnetResourceId = useExistingVirtualNetwork ? existingFunctionSubnet.id : functionSubnet.id

resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    tenantId: tenantId
    sku: {
      family: 'A'
      name: keyVaultSkuName
    }
    enablePurgeProtection: true
    enableRbacAuthorization: true
    softDeleteRetentionInDays: 90
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: productionProfile ? 'Deny' : 'Allow'
      virtualNetworkRules: productionProfile ? [
        { id: functionSubnetResourceId }
      ] : []
    }
  }
}

resource storageBlobRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, userAssignedIdentity.id, storageBlobDataOwnerRoleId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataOwnerRoleId)
    principalId: userAssignedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storageQueueRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, userAssignedIdentity.id, storageQueueDataContributorId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageQueueDataContributorId)
    principalId: userAssignedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storageTableRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, userAssignedIdentity.id, storageTableDataContributorId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageTableDataContributorId)
    principalId: userAssignedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource appInsightsRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(applicationInsights.id, userAssignedIdentity.id, monitoringMetricsPublisherId)
  scope: applicationInsights
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherId)
    principalId: userAssignedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource passkeyKeyOperatorRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, passkeyKeyOperatorRoleName)
  properties: {
    roleName: passkeyKeyOperatorRoleName
    description: 'Least-privilege Key Vault key operations required by the passkey Function sample.'
    type: 'CustomRole'
    assignableScopes: [resourceGroup().id]
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.KeyVault/vaults/keys/read'
          'Microsoft.KeyVault/vaults/keys/create/action'
          'Microsoft.KeyVault/vaults/keys/sign/action'
          'Microsoft.KeyVault/vaults/keys/verify/action'
          'Microsoft.KeyVault/vaults/secrets/getSecret/action'
          'Microsoft.KeyVault/vaults/secrets/setSecret/action'
          'Microsoft.KeyVault/vaults/secrets/delete'
        ]
        notDataActions: []
      }
    ]
  }
}

resource keyVaultPasskeyRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, userAssignedIdentity.id, passkeyKeyOperatorRole.id)
  scope: keyVault
  properties: {
    roleDefinitionId: passkeyKeyOperatorRole.id
    principalId: userAssignedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource developerStorageBlobRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!productionProfile && !empty(developerPrincipalId)) {
  name: guid(storage.id, developerPrincipalId, storageBlobDataContributorId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataContributorId)
    principalId: developerPrincipalId
  }
}

resource developerStorageQueueRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!productionProfile && !empty(developerPrincipalId)) {
  name: guid(storage.id, developerPrincipalId, storageQueueDataContributorId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageQueueDataContributorId)
    principalId: developerPrincipalId
  }
}

resource developerStorageTableRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!productionProfile && !empty(developerPrincipalId)) {
  name: guid(storage.id, developerPrincipalId, storageTableDataContributorId)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageTableDataContributorId)
    principalId: developerPrincipalId
  }
}

resource developerKeyVaultPasskeyRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!productionProfile && !empty(developerPrincipalId)) {
  name: guid(keyVault.id, developerPrincipalId, passkeyKeyOperatorRole.id)
  scope: keyVault
  properties: {
    roleDefinitionId: passkeyKeyOperatorRole.id
    principalId: developerPrincipalId
  }
}

resource appServicePlan 'Microsoft.Web/serverfarms@2024-11-01' = {
  name: planName
  location: location
  kind: 'functionapp'
  sku: {
    tier: 'FlexConsumption'
    name: 'FC1'
  }
  properties: {
    reserved: true
  }
  tags: tags
}

resource functionApp 'Microsoft.Web/sites@2024-11-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${userAssignedIdentity.id}': {}
    }
  }
  tags: tags
  dependsOn: [
    storageBlobRoleAssignment
    storageQueueRoleAssignment
    storageTableRoleAssignment
    appInsightsRoleAssignment
    keyVaultPasskeyRoleAssignment
  ]
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    virtualNetworkSubnetId: networkIntegrationEnabled ? functionSubnetResourceId : null
    siteConfig: {
      minTlsVersion: '1.2'
    }
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storage.properties.primaryEndpoints.blob}${deploymentStorageContainerName}'
          authentication: {
            type: 'UserAssignedIdentity'
            userAssignedIdentityResourceId: userAssignedIdentity.id
          }
        }
      }
      scaleAndConcurrency: {
        instanceMemoryMB: instanceMemoryMB
        maximumInstanceCount: maximumInstanceCount
      }
      runtime: {
        name: functionAppRuntime
        version: functionAppRuntimeVersion
      }
    }
  }
}

resource functionAppSettings 'Microsoft.Web/sites/config@2024-11-01' = {
  parent: functionApp
  name: 'appsettings'
  properties: {
    AzureWebJobsStorage__blobServiceUri: storage.properties.primaryEndpoints.blob
    AzureWebJobsStorage__queueServiceUri: storage.properties.primaryEndpoints.queue
    AzureWebJobsStorage__tableServiceUri: storage.properties.primaryEndpoints.table
    AzureWebJobsStorage__credential: 'managedidentity'
    AzureWebJobsStorage__clientId: userAssignedIdentity.properties.clientId
    PASSKEY_TENANT_ID: tenantId
    PASSKEY_KEYVAULT_NAME: keyVault.name
    PASSKEY_MANAGED_IDENTITY_CLIENT_ID: userAssignedIdentity.properties.clientId
    PASSKEY_OKTA_DOMAIN: oktaDomain
    PASSKEY_OKTA_REDIRECT_URI: oktaRedirectUri
    PASSKEY_ENTRA_PORTAL_ORIGIN: entraPortalOrigin
    PASSKEY_DEPLOYMENT_PROFILE: deploymentProfile
    PASSKEY_ALLOW_LOCAL_CREDENTIALS: 'false'
    PASSKEY_REGISTRATION_QUEUE_NAME: registrationQueueName
    PASSKEY_OKTA_REGISTRATION_QUEUE_NAME: oktaRegistrationQueueName
    PASSKEY_REGISTRATION_STATUS_CONTAINER_NAME: registrationStatusContainerName
    PASSKEY_CATALOG_TABLE_NAME: catalogTableName
    PASSKEY_CAPTURE_TABLE_NAME: captureTableName
    PASSKEY_CAPTURE_CONTAINER_NAME: captureContainerName
    PASSKEY_CAPTURE_MAX_BYTES: '1048576'
    PASSKEY_CAPTURE_PROVENANCE_DAYS: '90'
    PASSKEY_ENABLE_DEV_SECRET_EXPORT: (!productionProfile && enableDevelopmentSecretExport) ? 'true' : 'false'
    PASSKEY_POST_REGISTRATION_LOGIN_DELAY_SECONDS: '10'
    APPLICATIONINSIGHTS_CONNECTION_STRING: applicationInsights.properties.ConnectionString
    APPLICATIONINSIGHTS_AUTHENTICATION_STRING: 'ClientId=${userAssignedIdentity.properties.clientId};Authorization=AAD'
  }
}

resource keyVaultDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'send-to-log-analytics'
  scope: keyVault
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

resource blobDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'send-to-log-analytics'
  scope: storage::blobServices
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'Transaction'
        enabled: true
      }
    ]
  }
}

resource queueDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'send-to-log-analytics'
  scope: storage::queueServices
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'Transaction'
        enabled: true
      }
    ]
  }
}

resource tableDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'send-to-log-analytics'
  scope: storage::tableServices
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'Transaction'
        enabled: true
      }
    ]
  }
}

output functionAppName string = functionApp.name
output functionAppDefaultHostname string = functionApp.properties.defaultHostName
output keyVaultName string = keyVault.name
output keyVaultResourceId string = keyVault.id
output managedIdentityClientId string = userAssignedIdentity.properties.clientId
output managedIdentityPrincipalId string = userAssignedIdentity.properties.principalId
output storageAccountName string = storage.name
output storageAccountResourceId string = storage.id
output storageTableServiceUri string = storage.properties.primaryEndpoints.table
output catalogTableName string = catalogTableName
output catalogTableResourceId string = storage::tableServices::catalogTable.id
output captureTableResourceId string = storage::tableServices::captureTable.id
output captureContainerResourceId string = storage::blobServices::captureContainer.id
output deploymentContainerResourceId string = storage::blobServices::deploymentContainer.id
output registrationStatusContainerResourceId string = storage::blobServices::registrationStatusContainer.id
output registrationQueueResourceId string = storage::queueServices::registrationQueue.id
output oktaRegistrationQueueResourceId string = storage::queueServices::oktaRegistrationQueue.id
output developerPrincipalId string = developerPrincipalId
output managedIdentityStorageBlobRoleAssignmentId string = storageBlobRoleAssignment.id
output managedIdentityStorageQueueRoleAssignmentId string = storageQueueRoleAssignment.id
output managedIdentityStorageTableRoleAssignmentId string = storageTableRoleAssignment.id
output managedIdentityKeyVaultRoleAssignmentId string = keyVaultPasskeyRoleAssignment.id
output deploymentProfile string = deploymentProfile
output networkIntegrationEnabled bool = networkIntegrationEnabled
output existingVirtualNetworkResourceId string = useExistingVirtualNetwork ? existingVirtualNetwork.id : ''
output existingFunctionSubnetResourceId string = useExistingVirtualNetwork ? existingFunctionSubnet.id : ''
