// The Function App for phishing-inbox-triage, as infrastructure.
//
// Deploys, into an existing resource group:
//
//   * a Flex Consumption plan and a Linux / Python function app
//   * a storage account with shared-key access disabled, holding the
//     deployment package and the app's state, exports and reports
//   * a user-assigned managed identity the app uses for storage, Application
//     Insights, and (after you grant it, see the README) Microsoft Graph
//   * Application Insights on a Log Analytics workspace, with local auth off
//   * the PHISH_* app settings, starting in dry-run mode
//
// It does not grant Graph permissions or mailbox access: Entra and Exchange
// are outside ARM. The outputs give you the ids those steps need.
//
// Deploy with:
//
//   az deployment group create -g <rg> -f azure-function/infra/main.bicep \
//       -p appName=<app> mailbox=phish@contoso.com \
//          orgDomains=contoso.com,contoso.eu denyCheck=ceo@contoso.com \
//       --query properties.outputs
//
// Then publish the code (package.sh, then the deploy workflow or `func`).

@description('Globally unique name of the function app. Also its default hostname. At most 55 characters, so the names derived from it fit their limits.')
@minLength(2)
@maxLength(55)
param appName string

@description('Region for everything. Flex Consumption is not in every region; check `az functionapp list-flexconsumption-locations`.')
param location string = resourceGroup().location

@description('Python version for the app. 3.11 is the version the wrapper is documented and tested against in CI.')
@allowed(['3.11', '3.12', '3.13'])
param pythonVersion string = '3.11'

@description('The shared phishing reporting mailbox (PHISH_MAILBOX).')
param mailbox string

@description('Comma-separated list of your email domains (PHISH_ORG_DOMAINS).')
param orgDomains string

@description('Comma-separated sensitive mailboxes that must return 403, proving the mailbox scope (PHISH_DENY_CHECK). Every run checks these before reading mail.')
param denyCheck string

@description('NCRONTAB schedule for graph_submit.py (PHISH_SUBMIT_SCHEDULE).')
param submitSchedule string = '0 */15 * * * *'

@description('NCRONTAB schedule for collect_export.py + triage.py (PHISH_TRIAGE_SCHEDULE).')
param triageSchedule string = '0 0 6,18 * * *'

@description('Run the submit job no more often than every this many hours, however often its timer fires. 0 is off. NCRONTAB cannot say "every 36 hours" and a TimeSpan schedule is not allowed on Flex Consumption, so set submitSchedule to hourly (0 0 * * * *) and this to 36. A failed run is retried on the next firing.')
@minValue(0)
param submitMinIntervalHours int = 0

@description('The same for the triage job: set triageSchedule hourly (for example 0 30 * * * *) and this to 36.')
@minValue(0)
param triageMinIntervalHours int = 0

@description('How far back the triage job collects (PHISH_TRIAGE_SINCE), such as 24h or 2d. Make it longer than the interval so runs overlap: 48h for a 36 hour interval. Overlap is safe because Sentinel alerts once per item.')
param triageSince string = '24h'

@description('Start in dry-run mode: list and log what would be submitted, submit nothing. Flip to false once a dry run looks right.')
param dryRun bool = true

@description('Deploy with the collect_and_triage function disabled, leaving only submissions.')
param disableTriage bool = false

@description('Blob container for state, exports and reports (PHISH_STORAGE_CONTAINER).')
param dataContainerName string = 'phish-triage'

@description('Any further PHISH_* settings, as a key/value object. Overrides the settings this template sets. Example: { PHISH_CAPTURE_REPORTER_NOTE: \'true\', PHISH_MAX: \'50\' }')
param extraAppSettings object = {}

@description('Logs ingestion endpoint of the Sentinel data collection endpoint (PHISH_SENTINEL_DCE_ENDPOINT). Leave empty to not send to Sentinel. See sentinel/README.md.')
param sentinelDceEndpoint string = ''

@description('Immutable id of the Sentinel data collection rule (PHISH_SENTINEL_DCR_IMMUTABLE_ID). Set together with sentinelDceEndpoint.')
param sentinelDcrImmutableId string = ''

@description('Resource id of an existing Log Analytics workspace for Application Insights. Leave empty to create one.')
param logAnalyticsWorkspaceId string = ''

@description('Days of retention in the Log Analytics workspace this template creates.')
@minValue(30)
@maxValue(730)
param logRetentionDays int = 30

@description('Maximum instances the plan may scale out to. The timers run as singletons, so 40 (the minimum) is plenty.')
@minValue(40)
@maxValue(1000)
param maximumInstanceCount int = 40

@description('Memory per instance, in MB.')
@allowed([2048, 4096])
param instanceMemoryMB int = 2048

@description('Create the role assignments the identity needs on storage and Application Insights. Needs Owner or User Access Administrator on the resource group. Set false to deploy with Contributor only, then have an administrator make the five assignments listed in azure-function/README.md; the app cannot start until they exist.')
param assignRoles bool = true

@description('Tags applied to every resource.')
param tags object = {}

// ---------------------------------------------------------------------------

var token = toLower(uniqueString(resourceGroup().id, appName))
var storageName = take('st${replace(toLower(appName), '-', '')}${token}', 24)
var deploymentContainerName = 'app-package-${take(toLower(appName), 32)}-${take(token, 7)}'

var roles = {
  storageBlobDataOwner: 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
  storageBlobDataContributor: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
  storageQueueDataContributor: '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
  storageTableDataContributor: '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
  monitoringMetricsPublisher: '3913510d-42f4-4e42-8a64-420c390055eb'
}

// Both or neither: the runner refuses one without the other at startup, and
// this fails the deployment instead, which is earlier.
var sentinelSet = !empty(sentinelDceEndpoint) || !empty(sentinelDcrImmutableId)
var sentinelComplete = !empty(sentinelDceEndpoint) && !empty(sentinelDcrImmutableId)

// ---------------------------------------------------------------------------
// Identity, storage, monitoring

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${appName}'
  location: location
  tags: tags
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    // No keys: the host, the deployment and the runner all use the identity.
    allowSharedKeyAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
  }
  resource blobServices 'blobServices' = {
    name: 'default'
    properties: {
      deleteRetentionPolicy: {
        enabled: true
        days: 14
      }
    }
    resource deploymentContainer 'containers' = {
      name: deploymentContainerName
      properties: { publicAccess: 'None' }
    }
    // The runner creates this on first run too; creating it here means the
    // container exists before anyone looks for it.
    resource dataContainer 'containers' = {
      name: dataContainerName
      properties: { publicAccess: 'None' }
    }
  }
}

// The Functions host needs blob (and for some features queue and table) access
// to AzureWebJobsStorage; the runner needs blob access to the data container;
// the platform needs blob access to the deployment container.
resource storageRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for role in [
  roles.storageBlobDataOwner
  roles.storageBlobDataContributor
  roles.storageQueueDataContributor
  roles.storageTableDataContributor
]: if (assignRoles) {
  name: guid(storage.id, identity.id, role)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', role)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}]

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (empty(logAnalyticsWorkspaceId)) {
  name: 'log-${appName}'
  location: location
  tags: tags
  properties: {
    retentionInDays: logRetentionDays
    sku: { name: 'PerGB2018' }
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: 'appi-${appName}'
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: empty(logAnalyticsWorkspaceId) ? logAnalytics.id : logAnalyticsWorkspaceId
    DisableLocalAuth: true
  }
}

resource appInsightsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (assignRoles) {
  name: guid(appInsights.id, identity.id, roles.monitoringMetricsPublisher)
  scope: appInsights
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.monitoringMetricsPublisher)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
// Plan and app

resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: 'plan-${appName}'
  location: location
  tags: tags
  kind: 'functionapp'
  sku: {
    tier: 'FlexConsumption'
    name: 'FC1'
  }
  properties: {
    reserved: true
  }
}

var baseSettings = {
  // Host storage and telemetry, over the identity.
  AzureWebJobsStorage__accountName: storage.name
  AzureWebJobsStorage__credential: 'managedidentity'
  AzureWebJobsStorage__clientId: identity.properties.clientId
  APPLICATIONINSIGHTS_CONNECTION_STRING: appInsights.properties.ConnectionString
  APPLICATIONINSIGHTS_AUTHENTICATION_STRING: 'ClientId=${identity.properties.clientId};Authorization=AAD'

  // The runner: credentials and storage.
  PHISH_GRAPH_AUTH: 'managed_identity'
  PHISH_MANAGED_IDENTITY_CLIENT_ID: identity.properties.clientId
  PHISH_STORAGE_ACCOUNT_URL: storage.properties.primaryEndpoints.blob
  PHISH_STORAGE_CONTAINER: dataContainerName

  // The runner: the jobs.
  PHISH_SUBMIT_SCHEDULE: submitSchedule
  PHISH_TRIAGE_SCHEDULE: triageSchedule
  PHISH_SUBMIT_MIN_INTERVAL_HOURS: string(submitMinIntervalHours)
  PHISH_TRIAGE_MIN_INTERVAL_HOURS: string(triageMinIntervalHours)
  PHISH_TRIAGE_SINCE: triageSince
  PHISH_MAILBOX: mailbox
  PHISH_ORG_DOMAINS: orgDomains
  PHISH_DENY_CHECK: denyCheck
  PHISH_DRY_RUN: dryRun ? 'true' : 'false'
  'AzureWebJobs.collect_and_triage.Disabled': disableTriage ? 'true' : 'false'
}

var sentinelSettings = sentinelComplete ? {
  PHISH_SENTINEL_DCE_ENDPOINT: sentinelDceEndpoint
  PHISH_SENTINEL_DCR_IMMUTABLE_ID: sentinelDcrImmutableId
} : (sentinelSet ? fail('Set both sentinelDceEndpoint and sentinelDcrImmutableId, or neither.') : {})

resource functionApp 'Microsoft.Web/sites@2024-04-01' = {
  name: appName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
    }
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storage.properties.primaryEndpoints.blob}${deploymentContainerName}'
          authentication: {
            type: 'UserAssignedIdentity'
            userAssignedIdentityResourceId: identity.id
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: maximumInstanceCount
        instanceMemoryMB: instanceMemoryMB
      }
      runtime: {
        name: 'python'
        version: pythonVersion
      }
    }
  }
  // The role assignments must exist before the platform first reads the
  // deployment container with this identity.
  dependsOn: [
    storageRoles
  ]

  resource appSettings 'config' = {
    name: 'appsettings'
    properties: union(baseSettings, sentinelSettings, extraAppSettings)
  }
}

// ---------------------------------------------------------------------------

@description('The function app name, for the deploy workflow and `func`.')
output functionAppName string = functionApp.name

@description('The storage account that holds state, exports and reports.')
output storageAccountName string = storage.name

@description('Blob container with state/, runs/, exports/ and reports/.')
output dataContainerName string = dataContainerName

@description('Principal (object) id of the identity: the Graph app-role grant and sentinel/main.bicep need this.')
output identityPrincipalId string = identity.properties.principalId

@description('Client (application) id of the identity: the Exchange RBAC steps need this.')
output identityClientId string = identity.properties.clientId

@description('Resource id of the identity.')
output identityResourceId string = identity.id

@description('Application Insights resource, for the failed-invocation alert.')
output appInsightsName string = appInsights.name

@description('Scope for the four storage role assignments, if assignRoles was false.')
output storageAccountId string = storage.id

@description('Scope for the Monitoring Metrics Publisher assignment, if assignRoles was false.')
output appInsightsId string = appInsights.id
