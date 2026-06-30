targetScope = 'resourceGroup'

@description('Location for all Logic App workflows.')
param location string = resourceGroup().location

@description('Short environment suffix used in workflow names.')
param environmentName string = 'sample'

@description('Base URL for the passkey Function App, without a trailing slash.')
param functionBaseUrl string

@secure()
@description('Function key used to call the passkey Function endpoints.')
param functionKey string

@description('Optional tags to apply to the Logic App workflows.')
param tags object = {}

var workflowToken = take(uniqueString(resourceGroup().id, environmentName, functionBaseUrl), 8)
var tapWorkflowDefinition = loadJsonContent('workflows/register-via-tap.json')
var estsAuthWorkflowDefinition = loadJsonContent('workflows/register-via-estsauth.json')
var loginWorkflowDefinition = loadJsonContent('workflows/login-with-passkey.json')

resource registerViaTap 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'la-passkey-tap-${workflowToken}'
  location: location
  tags: union(tags, {
    displayName: 'Passkey register via TAP'
  })
  properties: {
    state: 'Enabled'
    definition: tapWorkflowDefinition
    parameters: {
      functionBaseUrl: {
        value: functionBaseUrl
      }
      functionKey: {
        value: functionKey
      }
    }
  }
}

resource registerViaEstsAuth 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'la-passkey-ests-${workflowToken}'
  location: location
  tags: union(tags, {
    displayName: 'Passkey register via ESTSAUTH'
  })
  properties: {
    state: 'Enabled'
    definition: estsAuthWorkflowDefinition
    parameters: {
      functionBaseUrl: {
        value: functionBaseUrl
      }
      functionKey: {
        value: functionKey
      }
    }
  }
}

resource loginWithPasskey 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'la-passkey-login-${workflowToken}'
  location: location
  tags: union(tags, {
    displayName: 'Passkey login'
  })
  properties: {
    state: 'Enabled'
    definition: loginWorkflowDefinition
    parameters: {
      functionBaseUrl: {
        value: functionBaseUrl
      }
      functionKey: {
        value: functionKey
      }
    }
  }
}

output registerViaTapWorkflowName string = registerViaTap.name
output registerViaEstsAuthWorkflowName string = registerViaEstsAuth.name
output loginWithPasskeyWorkflowName string = loginWithPasskey.name
