targetScope = 'resourceGroup'

@description('Deployment location')
param location string = resourceGroup().location

@description('Environment name from azd')
param environmentName string = 'dev'

@description('Deploy optional Web App hosting component')
param includeWebAppOption string = 'false'

@description('Enable Exchange Online connectivity and permissions for Maester')
param includeExchangeOption string = 'false'

@description('Enable Microsoft Teams connectivity and permissions for Maester')
param includeTeamsOption string = 'false'

@description('Enable Azure RBAC role assignments for Maester')
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

resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = if (includeWebApp) {
  name: appServicePlanName
  location: location
  tags: resourceTags
  sku: {
    name: webAppSkuName
    capacity: 1
  }
  kind: 'linux'
  properties: {
    reserved: true
  }
}

resource webApp 'Microsoft.Web/sites@2023-12-01' = if (includeWebApp) {
  name: webAppName
  location: location
  tags: resourceTags
  kind: 'app,linux'
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'NODE|22-lts'
      appCommandLine: 'pm2 serve /home/site/wwwroot --no-daemon --spa'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'STORAGE_ACCOUNT_NAME'
          value: storageAccount.name
        }
        {
          name: 'DASHBOARD_BLOB_PATH'
          value: 'latest/latest.html'
        }
      ]
    }
  }
}

resource webAppScmBasicAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = if (includeWebApp) {
  name: 'scm'
  parent: webApp
  properties: {
    allow: false
  }
}

resource webAppFtpBasicAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = if (includeWebApp) {
  name: 'ftp'
  parent: webApp
  properties: {
    allow: false
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

resource webAppDeleteLock 'Microsoft.Authorization/locks@2020-05-01' = if (includeWebApp && enableResourceLocks) {
  name: 'lock-cannot-delete-webapp'
  scope: webApp
  properties: {
    level: 'CanNotDelete'
    notes: 'Prevents accidental deletion of Maester web app resources.'
  }
}

output storageAccountName string = storageAccount.name
output webAppName string = includeWebApp ? webApp.name : ''
output webAppDefaultHostName string = includeWebApp ? webApp!.properties.defaultHostName : ''
output azureRbacScopes string = azureRbacScopes
output mailRecipient string = mailRecipient
