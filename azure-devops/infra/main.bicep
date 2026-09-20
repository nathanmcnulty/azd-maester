targetScope = 'resourceGroup'

@description('Deployment location')
@metadata({
  azd: {
    type: 'location'
    default: 'eastus2'
  }
})
param location string = resourceGroup().location

@description('Environment name from azd')
param environmentName string = 'dev'

@description('Deploy optional Web App hosting component')
@allowed([
  'true'
  'false'
])
@metadata({
  azd: {
    default: 'false'
  }
})
param includeWebAppOption string = 'false'

@description('Enable Exchange Online connectivity and permissions for Maester')
@allowed([
  'true'
  'false'
])
@metadata({
  azd: {
    default: 'false'
  }
})
param includeExchangeOption string = 'false'

@description('Enable Microsoft Teams connectivity and permissions for Maester')
@allowed([
  'true'
  'false'
])
@metadata({
  azd: {
    default: 'false'
  }
})
param includeTeamsOption string = 'false'

@description('Enable Azure RBAC role assignments for Maester')
@allowed([
  'true'
  'false'
])
@metadata({
  azd: {
    default: 'false'
  }
})
param includeAzureOption string = 'false'

@description('JSON array string of Azure scopes for RBAC assignments (management groups and/or subscriptions)')
param azureRbacScopes string = '[]'

@description('Optional mail recipient address for Maester report notifications')
param mailRecipient string = ''

@description('Optional Web App SKU for hosting report access portal')
param webAppSkuName string = 'F1'

@description('Enable can-not-delete locks on key resources')
param enableResourceLocks bool = true

@description('Optional custom tags merged onto top-level resources')
param customTags object = {}

var resourceSuffix = toLower(uniqueString(resourceGroup().id, environmentName))
var storageAccountName = 'stmaester${resourceSuffix}'
var appServicePlanName = 'asp-${toLower(environmentName)}'
var webAppName = 'app-maester-${resourceSuffix}'
var includeWebApp = toLower(includeWebAppOption) == 'true'

var defaultTags = {
  workload: 'maester'
  solution: 'azure-devops'
  environment: toLower(environmentName)
  managedBy: 'azd'
  includeExchange: toLower(includeExchangeOption)
  includeTeams: toLower(includeTeamsOption)
  includeAzure: toLower(includeAzureOption)
}
var resourceTags = union(defaultTags, customTags)

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: resourceTags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    accessTier: 'Hot'
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  name: 'default'
  parent: storageAccount
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 1
      allowPermanentDelete: true
    }
    isVersioningEnabled: false
  }
}

resource containerArchive 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  name: 'archive'
  parent: blobService
  properties: {
    publicAccess: 'None'
  }
}

resource containerLatest 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  name: 'latest'
  parent: blobService
  properties: {
    publicAccess: 'None'
  }
}

resource storageManagementPolicy 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = {
  name: 'default'
  parent: storageAccount
  properties: {
    policy: {
      rules: [
        {
          name: 'archiveTieringPolicy'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: [
                'blockBlob'
              ]
              prefixMatch: [
                'archive/'
              ]
            }
            actions: {
              baseBlob: {
                tierToCold: {
                  daysAfterModificationGreaterThan: 180
                }
                delete: {
                  daysAfterModificationGreaterThan: 365
                }
              }
            }
          }
        }
      ]
    }
  }
}

module maesterWebApp './vendor/Azd.MaesterReportWebApp/maester-report-webapp.bicep' = if (includeWebApp) {
  name: 'maester-report-webapp'
  params: {
    location: location
    environmentName: environmentName
    solutionName: 'azure-devops'
    appServicePlanName: appServicePlanName
    webAppName: webAppName
    storageAccountName: storageAccount.name
    webAppSkuName: webAppSkuName
    customTags: resourceTags
    enableResourceLocks: enableResourceLocks
    systemAssignedIdentity: false
    publisherPrincipalId: ''
    publisherResourceId: ''
  }
}

resource storageDeleteLock 'Microsoft.Authorization/locks@2020-05-01' = if (enableResourceLocks) {
  name: 'lock-cannot-delete-storage'
  scope: storageAccount
  properties: {
    level: 'CanNotDelete'
    notes: 'Prevents accidental deletion of Maester storage resources.'
  }
}

output storageAccountName string = storageAccount.name
output webAppName string = includeWebApp ? maesterWebApp!.outputs.webAppName : ''
output webAppDefaultHostName string = includeWebApp ? maesterWebApp!.outputs.webAppDefaultHostName : ''
output azureRbacScopes string = azureRbacScopes
output mailRecipient string = mailRecipient
