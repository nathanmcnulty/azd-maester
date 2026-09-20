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

@description('Container image to use for the Maester job')
param imageName string = 'mcr.microsoft.com/powershell:lts-mariner-2.0'

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

@description('Deploy Azure Container Registry and build custom Maester image')
@allowed([
  'true'
  'false'
])
@metadata({
  azd: {
    default: 'false'
  }
})
param includeACROption string = 'false'

@description('Enable can-not-delete locks on key resources')
param enableResourceLocks bool = true

@description('Optional custom tags merged onto top-level resources')
param customTags object = {}

// Standardized parameters and tags for consistency with automation-account and function-app
var managedEnvironmentName = 'cae-${toLower(environmentName)}'
var containerAppJobName = 'caj-maester-${toLower(environmentName)}'
var resourceSuffix = toLower(uniqueString(resourceGroup().id, environmentName))
var storageAccountName = 'stmaester${resourceSuffix}'
var acrName = 'crmaester${resourceSuffix}'
var fileShareName = 'scripts'
var storageBlobDataContributorRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
)
var acrPullRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '7f951dda-4ed3-4680-a7ca-43fe172d538d'
)
var appServicePlanName = 'asp-${toLower(environmentName)}'
var webAppName = 'app-maester-${resourceSuffix}'
var includeWebApp = toLower(includeWebAppOption) == 'true'
var includeACR = toLower(includeACROption) == 'true'
var defaultTags = {
  workload: 'maester'
  solution: 'container-app-job'
  environment: toLower(environmentName)
  managedBy: 'azd'
}
var resourceTags = union(defaultTags, customTags)

// ──────────────────────────────────────────────
// Storage Account (Azure Files for script mount + Blob for reports)
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
    allowSharedKeyAccess: true // Required for Azure Files volume mount in Container App Environment
    defaultToOAuthAuthentication: true
    accessTier: 'Hot'
  }
}

resource fileService 'Microsoft.Storage/storageAccounts/fileServices@2023-05-01' = {
  name: 'default'
  parent: storageAccount
}

resource fileShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-05-01' = {
  name: fileShareName
  parent: fileService
  properties: {
    shareQuota: 1
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

// ──────────────────────────────────────────────
// Container App Environment and Job
// ──────────────────────────────────────────────

resource managedEnvironment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: managedEnvironmentName
  location: location
  tags: resourceTags
  properties: {
    zoneRedundant: false
  }
}

resource managedEnvironmentStorage 'Microsoft.App/managedEnvironments/storages@2024-03-01' = {
  name: 'scriptstorage'
  parent: managedEnvironment
  properties: {
    azureFile: {
      accountName: storageAccount.name
      accountKey: storageAccount.listKeys().keys[0].value
      shareName: fileShare.name
      accessMode: 'ReadOnly'
    }
  }
}

resource containerAppJob 'Microsoft.App/jobs@2024-03-01' = {
  name: containerAppJobName
  location: location
  tags: resourceTags
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
  properties: {
    environmentId: managedEnvironment.id
    configuration: {
      triggerType: 'Schedule'
      scheduleTriggerConfig: {
        cronExpression: '0 0 * * 0'
        parallelism: 1
        replicaCompletionCount: 1
      }
      replicaRetryLimit: 1
      replicaTimeout: 3600
      // ACR registry is configured post-deployment by Build-MaesterImage.ps1 to avoid
      // a circular dependency: the Job's system identity needs AcrPull before provisioning
      // can validate ACR access, but AcrPull requires the Job's principalId.
      registries: []
    }
    template: {
      containers: [
        {
          name: 'maester'
          image: imageName
          command: [
            'pwsh'
            '-File'
            '/mnt/scripts/Invoke-MaesterContainerJob.ps1'
          ]
          env: [
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
          ]
          resources: {
            cpu: json('1.0')
            memory: '2Gi'
          }
          volumeMounts: [
            {
              volumeName: 'scripts'
              mountPath: '/mnt/scripts'
            }
          ]
        }
      ]
      volumes: [
        {
          name: 'scripts'
          storageType: 'AzureFile'
          storageName: managedEnvironmentStorage.name
        }
      ]
    }
  }
}

// ──────────────────────────────────────────────
// Optional Azure Container Registry
// ──────────────────────────────────────────────

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = if (includeACR) {
  name: acrName
  location: location
  tags: resourceTags
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
  }
}

resource acrPullRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (includeACR) {
  name: guid(acr.id, containerAppJob.id, 'AcrPull')
  scope: acr
  properties: {
    roleDefinitionId: acrPullRoleId
    principalId: containerAppJob.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ──────────────────────────────────────────────
// Role Assignments
// ──────────────────────────────────────────────

resource jobStorageBlobContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, containerAppJob.id, 'StorageBlobDataContributor')
  scope: storageAccount
  properties: {
    roleDefinitionId: storageBlobDataContributorRoleId
    principalId: containerAppJob.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ──────────────────────────────────────────────
// Optional Web App
// ──────────────────────────────────────────────

module maesterWebApp './vendor/Azd.MaesterReportWebApp/maester-report-webapp.bicep' = if (includeWebApp) {
  name: 'maester-report-webapp'
  params: {
    location: location
    environmentName: environmentName
    solutionName: 'container-app-job'
    appServicePlanName: appServicePlanName
    webAppName: webAppName
    storageAccountName: storageAccount.name
    webAppSkuName: webAppSkuName
    customTags: resourceTags
    enableResourceLocks: enableResourceLocks
    systemAssignedIdentity: true
    publisherPrincipalId: containerAppJob.identity.principalId
    publisherResourceId: containerAppJob.id
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

resource environmentDeleteLock 'Microsoft.Authorization/locks@2020-05-01' = if (enableResourceLocks) {
  name: 'lock-cannot-delete-environment'
  scope: managedEnvironment
  properties: {
    level: 'CanNotDelete'
    notes: 'Prevents accidental deletion of Maester container environment.'
  }
}

// ──────────────────────────────────────────────
// Outputs
// ──────────────────────────────────────────────

output containerAppJobName string = containerAppJob.name
output containerAppJobPrincipalId string = containerAppJob.identity.principalId
output storageAccountName string = storageAccount.name
output managedEnvironmentName string = managedEnvironment.name
output acrName string = includeACR ? acr.name : ''
output acrLoginServer string = includeACR ? acr!.properties.loginServer : ''
output webAppName string = includeWebApp ? maesterWebApp!.outputs.webAppName : ''
output webAppDefaultHostName string = includeWebApp ? maesterWebApp!.outputs.webAppDefaultHostName : ''
