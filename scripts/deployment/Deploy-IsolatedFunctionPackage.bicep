@description('Existing Flex Consumption Function App. Its public access and legacy-mutation settings must be verified before invoking this template.')
param functionAppName string

@description('Region of the existing Function App.')
param location string

@secure()
@description('HTTPS URL of a ready-to-run released-package.zip accessible to the deployment service. A short-lived SAS may be included.')
param packageUri string

resource functionApp 'Microsoft.Web/sites@2024-11-01' existing = {
  name: functionAppName
}

// OneDeploy retrieves the source package through ARM; it does not push from this client to SCM.
resource packageDeployment 'Microsoft.Web/sites/extensions@2022-09-01' = {
  parent: functionApp
  name: 'onedeploy'
  location: location
  properties: {
    packageUri: packageUri
    remoteBuild: false
  }
}
