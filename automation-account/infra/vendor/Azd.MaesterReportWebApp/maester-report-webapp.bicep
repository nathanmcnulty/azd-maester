@description('Azure region for the report web app resources.')
param location string

@description('azd environment name used in tags.')
param environmentName string

@description('Maester solution name used in tags.')
param solutionName string

@description('App Service plan name.')
param appServicePlanName string

@description('Web app name.')
param webAppName string

@description('Storage account name containing the generated report.')
param storageAccountName string

@description('App Service plan SKU.')
param webAppSkuName string = 'F1'

@description('Additional resource tags. These override the component defaults.')
param customTags object = {}

@description('Apply delete locks to the report web app resources.')
param enableResourceLocks bool = true

@description('Assign a system-managed identity to the report web app.')
param systemAssignedIdentity bool = false

@description('Principal that receives Website Contributor on the report web app. Leave empty to skip the role assignment.')
param publisherPrincipalId string = ''

@description('Principal type for the optional Website Contributor assignment.')
param publisherPrincipalType string = 'ServicePrincipal'

@description('Existing publisher resource ID used to preserve the original role-assignment name.')
param publisherResourceId string = ''

var resourceTags = union({
    workload: 'maester'
    solution: solutionName
    environment: toLower(environmentName)
    managedBy: 'azd'
  }, customTags)

resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: appServicePlanName
  location: location
  kind: 'linux'
  tags: resourceTags
  sku: {
    name: webAppSkuName
    capacity: 1
  }
  properties: {
    reserved: true
  }
}

resource webApp 'Microsoft.Web/sites@2023-12-01' = {
  name: webAppName
  location: location
  kind: 'app,linux'
  tags: resourceTags
  identity: systemAssignedIdentity ? {
    type: 'SystemAssigned'
  } : null
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
          value: storageAccountName
        }
        {
          name: 'DASHBOARD_BLOB_PATH'
          value: 'latest/latest.html'
        }
      ]
    }
  }
}

resource webAppScmBasicAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: webApp
  name: 'scm'
  properties: {
    allow: false
  }
}

resource webAppFtpBasicAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: webApp
  name: 'ftp'
  properties: {
    allow: false
  }
}

resource publisherWebsiteContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(publisherPrincipalId)) {
  name: guid(webApp.id, empty(publisherResourceId) ? publisherPrincipalId : publisherResourceId, 'WebsiteContributor')
  scope: webApp
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'de139f84-1756-47ae-9be6-808fbbe84772')
    principalId: publisherPrincipalId
    principalType: publisherPrincipalType
  }
}

resource webAppDeleteLock 'Microsoft.Authorization/locks@2020-05-01' = if (enableResourceLocks) {
  name: 'lock-cannot-delete-webapp'
  scope: webApp
  properties: {
    level: 'CanNotDelete'
    notes: 'Protect the optional Maester report web app from accidental deletion.'
  }
}

output webAppName string = webApp.name
output webAppDefaultHostName string = webApp.properties.defaultHostName
output webAppResourceId string = webApp.id
