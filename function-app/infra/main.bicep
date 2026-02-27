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

@description('Optional user-assigned managed identity resource id')
param userAssignedIdentityResourceId string = ''

@description('Optional mail recipient address for Maester report notifications')
param mailRecipient string = ''

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

@description('Optional Web App SKU for hosting report access portal')
param webAppSkuName string = 'F1'

@description('Enable can-not-delete locks on key resources')
param enableResourceLocks bool = true

@description('Function App hosting plan SKU: FC1 (Flex Consumption), B1 (App Service Basic), Y1 (Consumption)')
@allowed(['FC1', 'B1', 'Y1'])
@metadata({
  azd: {
    default: 'FC1'
  }
})
param functionAppPlan string = 'FC1'

@description('Optional custom tags merged onto top-level resources')
param customTags object = {}


var defaultTags = {
  workload: 'maester'
  solution: 'function-app'
  environment: toLower(environmentName)
  managedBy: 'azd'
}
var resourceTags = union(defaultTags, customTags)

var resourceSuffix = toLower(uniqueString(resourceGroup().id, environmentName))
var storageAccountName = 'stmaester${resourceSuffix}'
var hostingPlanName = 'plan-${toLower(environmentName)}'
var functionAppName = 'func-maester-${substring(resourceSuffix, 0, 12)}'
var storageBlobDataContributorRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
)
var websiteContributorRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'de139f84-1756-47ae-9be6-808fbbe84772'
)
var appServicePlanName = 'asp-${toLower(environmentName)}'
var webAppName = 'app-maester-${resourceSuffix}'
var includeWebApp = toLower(includeWebAppOption) == 'true'

// ──────────────────────────────────────────────
// Storage Account (Blob for reports + Function App internal storage)
// ──────────────────────────────────────────────

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
    allowSharedKeyAccess: true // Required for AzureWebJobsStorage connection string
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

resource containerDeploymentPackage 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = if (isFlexConsumption) {
  name: 'deploymentpackage'
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

// ──────────────────────────────────────────────
// Function App (Linux, PowerShell 7.4)
// Plan varies by functionAppPlan parameter:
//   Y1 = Consumption (Dynamic, 10-min timeout max)
//   B1 = App Service Basic (Dedicated, unlimited timeout)
//   FC1 = Flex Consumption (Serverless, 30-min+ timeout, no managed deps)
// ──────────────────────────────────────────────

var isConsumptionPlan = functionAppPlan == 'Y1'
var isFlexConsumption = functionAppPlan == 'FC1'
var isDedicatedPlan = !isConsumptionPlan && !isFlexConsumption

resource hostingPlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: hostingPlanName
  location: location
  tags: resourceTags
  sku: isConsumptionPlan
    ? {
        name: 'Y1'
        tier: 'Dynamic'
      }
    : isFlexConsumption
      ? {
          name: 'FC1'
          tier: 'FlexConsumption'
        }
      : {
          name: functionAppPlan
          tier: 'Basic'
        }
  kind: 'functionapp'
  properties: {
    reserved: true
  }
}

// FC1 manages runtime/extension version via functionAppConfig, not app settings
var functionAppFlexOnlySettings = isFlexConsumption
  ? []
  : [
      {
        name: 'FUNCTIONS_EXTENSION_VERSION'
        value: '~4'
      }
      {
        name: 'FUNCTIONS_WORKER_RUNTIME'
        value: 'powershell'
      }
    ]

var functionAppBaseAppSettings = union(functionAppFlexOnlySettings, [
  {
    name: 'AzureWebJobsStorage'
    value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'
  }
  {
    name: 'STORAGE_ACCOUNT_NAME'
    value: storageAccount.name
  }
  {
    name: 'INCLUDE_EXCHANGE'
    value: includeExchangeOption
  }
  {
    name: 'INCLUDE_TEAMS'
    value: includeTeamsOption
  }
  {
    name: 'INCLUDE_AZURE'
    value: includeAzureOption
  }
  {
    name: 'MAIL_RECIPIENT'
    value: mailRecipient
  }
  {
    name: 'WEB_APP_NAME'
    value: includeWebApp ? webAppName : ''
  }
  {
    name: 'WEB_APP_RESOURCE_GROUP_NAME'
    value: includeWebApp ? resourceGroup().name : ''
  }
])

// Consumption (Y1) requires Azure Files content share settings
var functionAppConsumptionAppSettings = isConsumptionPlan
  ? [
      {
        name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
        value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'
      }
      {
        name: 'WEBSITE_CONTENTSHARE'
        value: toLower(functionAppName)
      }
    ]
  : []

// siteConfig for non-Flex plans includes linuxFxVersion; FC1 sets runtime via functionAppConfig
var functionAppSiteConfigBase = {
  ftpsState: 'Disabled'
  alwaysOn: isDedicatedPlan
  appSettings: union(functionAppBaseAppSettings, functionAppConsumptionAppSettings)
}
var functionAppSiteConfig = isFlexConsumption
  ? functionAppSiteConfigBase
  : union(functionAppSiteConfigBase, { linuxFxVersion: 'PowerShell|7.4' })

var functionAppPropertiesBase = {
  serverFarmId: hostingPlan.id
  httpsOnly: true
  siteConfig: functionAppSiteConfig
}

// FC1 requires functionAppConfig with deployment storage, scale settings, and runtime
var functionAppFlexConfig = {
  functionAppConfig: {
    deployment: {
      storage: {
        type: 'blobContainer'
        value: '${storageAccount.properties.primaryEndpoints.blob}deploymentpackage'
        authentication: {
          type: 'SystemAssignedIdentity'
        }
      }
    }
    scaleAndConcurrency: {
      maximumInstanceCount: 40
      instanceMemoryMB: 2048
    }
    runtime: {
      name: 'powershell'
      version: '7.4'
    }
  }
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionAppName
  location: location
  tags: resourceTags
  kind: 'functionapp,linux'
  identity: empty(userAssignedIdentityResourceId)
    ? {
        type: 'SystemAssigned'
      }
    : {
        type: 'SystemAssigned, UserAssigned'
        userAssignedIdentities: {
          '${userAssignedIdentityResourceId}': {}
        }
      }
  properties: isFlexConsumption
    ? union(functionAppPropertiesBase, functionAppFlexConfig)
    : functionAppPropertiesBase
}

resource functionAppScmBasicAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  name: 'scm'
  parent: functionApp
  properties: {
    allow: false
  }
}

resource functionAppFtpBasicAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  name: 'ftp'
  parent: functionApp
  properties: {
    allow: false
  }
}

// ──────────────────────────────────────────────
// Role Assignments
// ──────────────────────────────────────────────

resource funcStorageBlobContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, functionApp.id, 'StorageBlobDataContributor')
  scope: storageAccount
  properties: {
    roleDefinitionId: storageBlobDataContributorRoleId
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ──────────────────────────────────────────────
// Optional Web App
// ──────────────────────────────────────────────

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
  dependsOn: [
    functionApp
  ]
}

resource webApp 'Microsoft.Web/sites@2023-12-01' = if (includeWebApp) {
  name: webAppName
  location: location
  tags: resourceTags
  kind: 'app,linux'
  identity: {
    type: 'SystemAssigned'
  }
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

resource funcWebAppContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (includeWebApp) {
  name: guid(webApp.id, functionApp.id, 'WebsiteContributor')
  scope: webApp
  properties: {
    roleDefinitionId: websiteContributorRoleId
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ──────────────────────────────────────────────
// Resource Locks
// ──────────────────────────────────────────────

resource storageDeleteLock 'Microsoft.Authorization/locks@2020-05-01' = if (enableResourceLocks) {
  name: 'lock-cannot-delete-storage'
  scope: storageAccount
  properties: {
    level: 'CanNotDelete'
    notes: 'Prevents accidental deletion of Maester storage resources.'
  }
}

resource functionAppDeleteLock 'Microsoft.Authorization/locks@2020-05-01' = if (enableResourceLocks) {
  name: 'lock-cannot-delete-functionapp'
  scope: functionApp
  properties: {
    level: 'CanNotDelete'
    notes: 'Prevents accidental deletion of Maester function app.'
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

// ──────────────────────────────────────────────
// Outputs
// ──────────────────────────────────────────────

output functionAppName string = functionApp.name
output functionAppPrincipalId string = functionApp.identity.principalId
output storageAccountName string = storageAccount.name
output webAppName string = includeWebApp ? webApp.name : ''
output webAppDefaultHostName string = includeWebApp ? webApp!.properties.defaultHostName : ''
