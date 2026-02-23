targetScope = 'resourceGroup'

@description('Deployment location')
param location string = resourceGroup().location

@description('Environment name from azd')
param environmentName string = 'dev'

@description('Optional user-assigned managed identity resource id')
param userAssignedIdentityResourceId string = ''

@description('Optional mail recipient address for Maester report notifications')
param mailRecipient string = ''

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

@description('Optional Web App SKU for hosting report access portal')
param webAppSkuName string = 'F1'

@description('Enable can-not-delete locks on key resources')
param enableResourceLocks bool = true

@description('Optional custom tags merged onto top-level resources')
param customTags object = {}

@description('Deployment timestamp used to compute a future schedule start time')
param deploymentTimestamp string = utcNow()

// Standardized parameters and tags for consistency with function-app and container-app-job
var automationAccountName = 'aa-${toLower(environmentName)}'
var scheduleName = 'maester-weekly-sunday'
var runbookName = 'maester-runbook'
var runtimeEnvironmentName = 'PowerShell-74-Maester'
var resourceSuffix = toLower(uniqueString(resourceGroup().id, environmentName))
var storageAccountName = 'stmaester${resourceSuffix}'
var storageBlobDataContributorRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
var websiteContributorRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'de139f84-1756-47ae-9be6-808fbbe84772')
var appServicePlanName = 'asp-${toLower(environmentName)}'
var webAppName = 'app-maester-${resourceSuffix}'
var includeWebApp = toLower(includeWebAppOption) == 'true'
var defaultTags = {
  workload: 'maester'
  solution: 'automation-account'
  environment: toLower(environmentName)
  managedBy: 'azd'
}
var resourceTags = union(defaultTags, customTags)

resource automationAccount 'Microsoft.Automation/automationAccounts@2024-10-23' = {
  name: automationAccountName
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
    sku: {
      name: 'Basic'
    }
    disableLocalAuth: true
    publicNetworkAccess: true
  }
}

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
  dependsOn: [
    automationAccount
  ]
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
  dependsOn: [
    automationAccount
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

resource automationStorageBlobContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, automationAccount.id, 'StorageBlobDataContributor')
  scope: storageAccount
  properties: {
    roleDefinitionId: storageBlobDataContributorRoleId
    principalId: automationAccount.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource automationWebAppContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (includeWebApp) {
  name: guid(webApp.id, automationAccount.id, 'WebsiteContributor')
  scope: webApp
  properties: {
    roleDefinitionId: websiteContributorRoleId
    principalId: automationAccount.identity.principalId
    principalType: 'ServicePrincipal'
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

resource automationDeleteLock 'Microsoft.Authorization/locks@2020-05-01' = if (enableResourceLocks) {
  name: 'lock-cannot-delete-automation'
  scope: automationAccount
  properties: {
    level: 'CanNotDelete'
    notes: 'Prevents accidental deletion of Maester automation resources.'
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

resource runtime74 'Microsoft.Automation/automationAccounts/runtimeEnvironments@2024-10-23' = {
  name: runtimeEnvironmentName
  parent: automationAccount
  location: location
  properties: {
    runtime: {
      language: 'PowerShell'
      version: '7.4'
    }
    defaultPackages: {}
    description: 'PowerShell 7.4 custom runtime environment for Maester runbooks'
  }
}

resource runtimePackageAzAccounts 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2024-10-23' = {
  name: 'Az.Accounts'
  parent: runtime74
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/Az.Accounts'
    }
  }
}

resource runtimePackageMaester 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2024-10-23' = {
  name: 'Maester'
  parent: runtime74
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/Maester'
    }
  }
}

resource runtimePackagePester 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2024-10-23' = {
  name: 'Pester'
  parent: runtime74
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/Pester'
    }
  }
}

resource runtimePackageNuGet 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2024-10-23' = {
  name: 'NuGet'
  parent: runtime74
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/NuGet'
    }
  }
}

resource runtimePackagePackageManagement 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2024-10-23' = {
  name: 'PackageManagement'
  parent: runtime74
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/PackageManagement'
    }
  }
}

resource runtimePackageGraphAuth 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2024-10-23' = {
  name: 'Microsoft.Graph.Authentication'
  parent: runtime74
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Authentication'
    }
  }
}

resource runtimePackageExchangeOnlineManagement 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2024-10-23' = {
  name: 'ExchangeOnlineManagement'
  parent: runtime74
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/ExchangeOnlineManagement'
    }
  }
}

resource runtimePackageMicrosoftTeams 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2024-10-23' = {
  name: 'MicrosoftTeams'
  parent: runtime74
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/MicrosoftTeams'
    }
  }
}

resource runbook 'Microsoft.Automation/automationAccounts/runbooks@2024-10-23' = {
  name: runbookName
  parent: automationAccount
  location: location
  properties: {
    runbookType: 'PowerShell'
    logProgress: true
    logVerbose: false
    description: 'Runbook to execute Maester report workflow'
    publishContentLink: {
      uri: 'https://raw.githubusercontent.com/maester365/maester/main/powershell/public/Invoke-Maester.ps1'
      version: '1.0.0'
    }
    runtimeEnvironment: runtime74.name
  }
  dependsOn: [
    runtimePackageAzAccounts
    runtimePackageMaester
    runtimePackagePester
    runtimePackageNuGet
    runtimePackagePackageManagement
    runtimePackageGraphAuth
    runtimePackageExchangeOnlineManagement
    runtimePackageMicrosoftTeams
  ]
}

resource variableStorageAccountName 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  name: 'StorageAccountName'
  parent: automationAccount
  properties: {
    description: 'Storage account name for persisted Maester outputs'
    isEncrypted: false
    value: '"${storageAccount.name}"'
  }
}

resource variableMailRecipient 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  name: 'MailRecipient'
  parent: automationAccount
  properties: {
    description: 'Optional recipient for Maester email notifications'
    isEncrypted: false
    value: '"${mailRecipient}"'
  }
}

resource variableIncludeExchange 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  name: 'IncludeExchange'
  parent: automationAccount
  properties: {
    description: 'Whether the runbook should attempt to connect to Exchange Online'
    isEncrypted: false
    value: '"${includeExchangeOption}"'
  }
}

resource variableIncludeTeams 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  name: 'IncludeTeams'
  parent: automationAccount
  properties: {
    description: 'Whether the runbook should attempt to connect to Microsoft Teams'
    isEncrypted: false
    value: '"${includeTeamsOption}"'
  }
}

resource variableIncludeAzure 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  name: 'IncludeAzure'
  parent: automationAccount
  properties: {
    description: 'Whether setup should grant Azure RBAC at the requested scopes'
    isEncrypted: false
    value: '"${includeAzureOption}"'
  }
}

resource variableAzureRbacScopes 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = {
  name: 'AzureRbacScopes'
  parent: automationAccount
  properties: {
    description: 'JSON array string of Azure RBAC scopes requested for the managed identity'
    isEncrypted: false
    value: '"${azureRbacScopes}"'
  }
}

resource variableWebAppName 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = if (includeWebApp) {
  name: 'WebAppName'
  parent: automationAccount
  properties: {
    description: 'Optional Web App name for publishing latest Maester dashboard as default content'
    isEncrypted: false
    value: '"${webApp.name}"'
  }
}

resource variableWebAppResourceGroupName 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = if (includeWebApp) {
  name: 'WebAppResourceGroupName'
  parent: automationAccount
  properties: {
    description: 'Resource group for optional Web App hosting latest Maester dashboard'
    isEncrypted: false
    value: '"${resourceGroup().name}"'
  }
}

resource schedule 'Microsoft.Automation/automationAccounts/schedules@2023-11-01' = {
  name: scheduleName
  parent: automationAccount
  properties: {
    startTime: dateTimeAdd(deploymentTimestamp, 'P7D')
    expiryTime: '2099-12-31T23:59:00Z'
    interval: 1
    frequency: 'Week'
    timeZone: 'UTC'
    advancedSchedule: {
      weekDays: [
        'Sunday'
      ]
    }
  }
}

resource jobSchedule 'Microsoft.Automation/automationAccounts/jobSchedules@2023-11-01' = {
  name: guid(automationAccount.id, scheduleName, runbookName)
  parent: automationAccount
  properties: {
    schedule: {
      name: schedule.name
    }
    runbook: {
      name: runbook.name
    }
  }
}

output automationAccountName string = automationAccount.name
output automationPrincipalId string = automationAccount.identity.principalId
output storageAccountName string = storageAccount.name
output webAppName string = includeWebApp ? webApp.name : ''
output webAppDefaultHostName string = includeWebApp ? webApp!.properties.defaultHostName : ''
