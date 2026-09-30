// Microsoft Sentinel integration for phishing-inbox-triage.
//
// Deploys, into an existing Log Analytics workspace that has Sentinel enabled:
//
//   * the custom table PhishTriage_CL (one row per queue item per triage run)
//   * a data collection endpoint and rule the Function App sends rows through
//   * the Monitoring Metrics Publisher role for the Function App's identity
//   * a scheduled analytics rule that opens an incident the first time an
//     item is triaged as an exception at P1 or P2
//
// Deploy with:
//
//   az deployment group create -g <workspace-rg> -f azure-function/sentinel/main.bicep \
//       -p workspaceName=<workspace> functionPrincipalId=<identity-principal-id>
//
// Then set on the Function App the two outputs this prints:
//   PHISH_SENTINEL_DCE_ENDPOINT      = dceLogsIngestionEndpoint
//   PHISH_SENTINEL_DCR_IMMUTABLE_ID  = dcrImmutableId

@description('Existing Log Analytics workspace with Microsoft Sentinel enabled.')
param workspaceName string

@description('Principal (object) id of the Function App\'s managed identity. Leave empty to skip the role assignment.')
param functionPrincipalId string = ''

@description('Region for the data collection endpoint and rule. Must match the workspace region.')
param location string = resourceGroup().location

@description('How long rows are kept in the table, in days.')
@minValue(4)
@maxValue(730)
param retentionInDays int = 90

@description('Priorities that open an incident.')
param incidentPriorities array = [
  'P1'
  'P2'
]

@description('Open incidents from the analytics rule. Set false to deploy the table and rule disabled, for a first look at the data.')
param analyticsRuleEnabled bool = true

var tableName = 'PhishTriage_CL'
var streamName = 'Custom-${tableName}'
var monitoringMetricsPublisher = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4e42-8a64-420c390055eb')

// The column list is the contract with runner.sentinel_rows(). A test in
// tests/test_function_runner.py checks every column the runner emits is
// declared here. Keep the two in step.
var columns = [
  { name: 'TimeGenerated', type: 'datetime' }
  { name: 'RunId', type: 'string' }
  { name: 'TriageId', type: 'string' }
  { name: 'Lane', type: 'string' }
  { name: 'GapReason', type: 'string' }
  { name: 'Priority', type: 'string' }
  { name: 'Categories', type: 'dynamic' }
  { name: 'Reporter', type: 'string' }
  { name: 'ReportedVia', type: 'string' }
  { name: 'Sender', type: 'string' }
  { name: 'Subject', type: 'string' }
  { name: 'RecipientCount', type: 'int' }
  { name: 'Vips', type: 'dynamic' }
  { name: 'Indicators', type: 'dynamic' }
  { name: 'InteractionTypes', type: 'dynamic' }
  { name: 'InjectionAttempt', type: 'boolean' }
  { name: 'SubmissionId', type: 'string' }
  { name: 'AirStatus', type: 'string' }
  { name: 'Verdict', type: 'string' }
  { name: 'UserNotified', type: 'boolean' }
  { name: 'DefenderActions', type: 'string' }
  { name: 'AirAgeHours', type: 'real' }
  { name: 'NotVerified', type: 'dynamic' }
  { name: 'Interaction', type: 'dynamic' }
  { name: 'Evidence', type: 'dynamic' }
  { name: 'Actions', type: 'dynamic' }
]

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource table 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspace
  name: tableName
  properties: {
    plan: 'Analytics'
    retentionInDays: retentionInDays
    schema: {
      name: tableName
      columns: columns
    }
  }
}

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: 'dce-phish-triage'
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: 'dcr-phish-triage'
  location: location
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      '${streamName}': {
        columns: columns
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'workspace'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [ streamName ]
        destinations: [ 'workspace' ]
        transformKql: 'source'
        outputStream: streamName
      }
    ]
  }
  dependsOn: [ table ]
}

resource publisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(functionPrincipalId)) {
  name: guid(dcr.id, functionPrincipalId, monitoringMetricsPublisher)
  scope: dcr
  properties: {
    roleDefinitionId: monitoringMetricsPublisher
    principalId: functionPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// An item alerts once: the first run in which it is an exception at one of
// the incident priorities. Later runs re-triage the same 24h window and emit
// the same TriageId again; the leftanti join drops those. The incident
// grouping on TriageId is a second net for a row that arrives late.
var priorityList = join(map(incidentPriorities, p => '"${p}"'), ', ')
var query = join([
  'let priorities = dynamic([${priorityList}]);'
  'PhishTriage_CL'
  '| where Lane == "exception" and Priority in (priorities)'
  '| join kind=leftanti ('
  '    PhishTriage_CL'
  '    | where TimeGenerated between (ago(7d) .. ago(2h))'
  '    | where Lane == "exception" and Priority in (priorities)'
  '    | distinct TriageId'
  '  ) on TriageId'
  '| extend Severity = case(Priority == "P1", "High", Priority == "P2", "Medium", "Low")'
  '| extend SenderAddress = iff(Sender has "<", extract(@"<([^>]+)>", 1, Sender), Sender)'
  '| extend CategoryList = strcat_array(Categories, ", "), IndicatorList = strcat_array(Indicators, ", ")'
  '| extend EvidenceText = strcat_array(Evidence, " | "), NextActions = strcat_array(Actions, " | ")'
  '| project TimeGenerated, RunId, TriageId, Priority, Severity, CategoryList, IndicatorList, Reporter, SenderAddress, Sender, Subject, RecipientCount, SubmissionId, AirStatus, Verdict, EvidenceText, NextActions'
], '\n')

resource rule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'phish-triage-exceptions')
  kind: 'Scheduled'
  properties: {
    displayName: 'Phishing triage: exception needs an analyst'
    description: 'A user-reported phishing item that phishing-inbox-triage routed to the exception lane at a priority that needs a person. The evidence and recommended actions are in the alert\'s custom details; the full handover report is in the Function App\'s Blob container under reports/.'
    enabled: analyticsRuleEnabled
    severity: 'High'
    query: query
    queryFrequency: 'PT1H'
    queryPeriod: 'PT2H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT1H'
    tactics: [
      'InitialAccess'
    ]
    techniques: [
      'T1566'
    ]
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'P7D'
        matchingMethod: 'Selected'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: [
          'TriageId'
        ]
      }
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: '{{Priority}} phishing triage: {{Subject}}'
      alertDescriptionFormat: 'Reported by {{Reporter}} from {{Sender}}. Categories: {{CategoryList}}. Defender verdict: {{Verdict}} ({{AirStatus}}). Evidence: {{EvidenceText}}'
      alertSeverityColumnName: 'Severity'
    }
    customDetails: {
      TriageId: 'TriageId'
      RunId: 'RunId'
      Priority: 'Priority'
      Categories: 'CategoryList'
      Indicators: 'IndicatorList'
      SubmissionId: 'SubmissionId'
      Verdict: 'Verdict'
      RecipientCount: 'RecipientCount'
      NextActions: 'NextActions'
    }
    entityMappings: [
      {
        entityType: 'Mailbox'
        fieldMappings: [
          { identifier: 'MailboxPrimaryAddress', columnName: 'Reporter' }
        ]
      }
      {
        entityType: 'MailMessage'
        fieldMappings: [
          { identifier: 'Sender', columnName: 'SenderAddress' }
          { identifier: 'Subject', columnName: 'Subject' }
          { identifier: 'Recipient', columnName: 'Reporter' }
        ]
      }
    ]
  }
}

output dceLogsIngestionEndpoint string = dce.properties.logsIngestion.endpoint
output dcrImmutableId string = dcr.properties.immutableId
output tableName string = tableName
output streamName string = streamName
