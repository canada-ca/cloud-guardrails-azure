Param
(
    [Parameter (Mandatory= $true)]
    [String] $tenantOrganizationName,   

    [Parameter (Mandatory= $true)]
    [String] $useRunbookRunAsAccount,

    [Parameter (Mandatory= $true)]
    [String] $resultsStorageAccountResourceGroupName,

    [Parameter (Mandatory= $true)]
    [String] $resultsStorageAccountName,

    [Parameter (Mandatory= $true)]
    [String] $resultsContainerName,

    [Parameter (Mandatory= $false)]
    [String] $readerAccountCredentialName
)

$ErrorActionPreference = "Stop"


# ----------------------- Configurable settings start ------------------------------

# ----------------------- Configurable settings end ------------------------------

$tempFilePath = $env:TEMP

$blueprintDefinitionsPathPrefix = "cloud-guardrails-azure-master\toolbox"
$blueprintDefinitionFolderName = "gc-guardrail-blueprint-definitions"
$policyDefinitionsZippedPath = "$tempFilePath\PBMMComplianceVerification.zip"
$policyDefinitionsUnzippedPath = "$tempFilePath\PBMM-Compliance-Verification"
$policyArtifactsFileName = "policy-artifact-list.json"
$repoUrl = "https://github.com/tacummins1/testtbsrepo/archive/master.zip"

# TODO unhardcode these later to support multiple environment profiles

$blueprintEnvironmentFolder = "pbmm-profile-6"
$blueprintTypeFolder = "30-day-guardrails"

$policyArtifactListFilePath = "$policyDefinitionsUnzippedPath\$blueprintDefinitionsPathPrefix\$blueprintDefinitionFolderName\$blueprintEnvironmentFolder\$blueprintTypeFolder\$policyArtifactsFileName"

$complianceVerificationResultsFileName = "$tenantOrganizationName.json"
$complianceVerificationResultsFilePath = "$tempFilePath\$complianceVerificationResultsFileName"

$complianceVerificationResultTextFileName = "$tenantOrganizationName.txt"
$complianceVerificationResultsTextFilePath = "$tempFilePath\$complianceVerificationResultTextFileName"

Add-Type -AssemblyName System.IO.Compression.FileSystem

# Unzip function
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    Remove-Item -Path $outpath -Recurse -ErrorAction Ignore
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}

function outputText($text)
{
    $text | Add-Content -Path $complianceVerificationResultsTextFilePath -Encoding "UTF8"
}

function outputComplianceResultAsText($subscriptionComplianceResults) {

    outputText "Tenant ${tenantOrganizationName} PBMM Policy Compliance Results as at $((Get-Date).ToString()) UTC"
    outputText "--------------------------------------------------------------------------------------------------------"
    outputText ""
    outputText "Compliance summary"
    outputText "------------------"
    foreach ($subscriptionComplianceResult in $subscriptionComplianceResults) {
        outputText ""
        outputText "Subscription: $($subscriptionComplianceResult.subscriptionId)"
        outputText "--------------------------------------------------------------"
        outputText "Number of missing PBMM blueprint policies: $($subscriptionComplianceResult.numMissingPolicies)"
        outputText "Number of non-compliant resources: $($subscriptionComplianceResult.numNonCompliantResources)"
        outputText "Has policy scope exclusions: $($subscriptionComplianceResult.hasPolicyExclusions)"
        outputText "Number of subnets with direct route to the internet which are designated as perimeter/edge gateway subnets: $($subscriptionComplianceResult.numSubnetsWithDirectRouteToInternetAuthorized)"
        outputText "Number of subnets with direct route to the internet which are NOT designated as perimeter/edge gateway subnets: $($subscriptionComplianceResult.numSubnetsWithDirectRouteToInternetUnauthorized)"
        outputText "Number of network interfaces with Public IPs which are designated as Perimeter UTM Firewall interfaces: $($subscriptionComplianceResult.numNetworkInterfacesWithPublicIPAuthorized)"
        outputText "Number of network interfaces with Public IPs which are NOT designated as Perimeter UTM Firewall interfaces: $($subscriptionComplianceResult.numNetworkInterfacesWithPublicIPUnauthorized)"
        outputText "Number of public storage account containers: $($subscriptionComplianceResult.publicStorageAccountContainers.Count)"
    }

    outputText ""
    outputText ""
    outputText "Compliance details"
    outputText "------------------"   
    foreach ($subscriptionComplianceResult in $subscriptionComplianceResults) {
        outputText ""
        outputText "Subscription: $($subscriptionComplianceResult.subscriptionId)"
        outputText "--------------------------------------------------------------"
        outputText ""
        outputText "Missing policy assignments"
        outputText "--------------------------" 
        outputText ""             
        if ($subscriptionComplianceResult.missingPolicies.Count -gt 0) {
            foreach ($missingPolicy in $subscriptionComplianceResult.missingPolicies) {
                $policyDisplayName = $missingPolicy.policyDefinitionDisplayName
                outputText "  $policyDisplayName"
            }
        }
        else {
            outputText "  There are no missing policy assignments"
        }

        outputText "" 
        outputText "" 
        outputText "Non-compliant resources"
        outputText "------------------------"

        foreach ($nonCompliantResourcesSummary in $subscriptionComplianceResult.nonCompliantResources) {
            outputText ""
            outputText "For policy '$($nonCompliantResourcesSummary.policyDisplayName)':"
            foreach ($nonCompliantResouceId in $nonCompliantResourcesSummary.nonCompliantResources) {
                outputText "  $nonCompliantResouceId"
            }
        }

        outputText "" 
        outputText "" 
        outputText "Authorized subnets with direct route to the internet"
        outputText "----------------------------------------------------"
        outputText ""
        foreach ($subnet in $subscriptionComplianceResult.authorizedSubnetsWithDirectRouteToInternet) {
            outputText "  $subnet"
        }

        outputText "" 
        outputText "" 
        outputText "Unauthorized subnets with direct route to the internet"
        outputText "------------------------------------------------------"
        outputText ""
        foreach ($subnet in $subscriptionComplianceResult.unauthorizedSubnetsWithDirectRouteToInternet) {
            outputText "  $subnet"
        }

        outputText "" 
        outputText "" 
        outputText "Authorized network interfaces with public IPs"
        outputText "---------------------------------------------"
        outputText ""
        foreach ($networkInterface in $subscriptionComplianceResult.authorizedNetworkInterfacesWithPublicIPs) {
            outputText "  $networkInterface"
        }

        outputText "" 
        outputText "" 
        outputText "Unauthorized network interfaces with public IPs"
        outputText "-----------------------------------------------"
        outputText ""
        foreach ($networkInterface in $subscriptionComplianceResult.unauthorizedNetworkInterfacesWithPublicIPs) {
            outputText "  $networkInterface"
        }

        outputText "" 
        outputText "" 
        outputText "Storage account containers with unauthenticated access"
        outputText "------------------------------------------------------"
        outputText ""
        foreach ($storageAccountContainer in $subscriptionComplianceResult.publicStorageAccountContainers) {
            outputText ""            
            outputText "  $($storageAccountContainer.publicContainerDetails)"
            outputText "    Firewall rules:"
            if ($storageAccountContainer.firewallAllowedIPsAndVnetSubnets.Count -gt 0) {
                foreach ($firewallRule in $storageAccountContainer.firewallAllowedIPsAndVnetSubnets) {
                    outputText "      $firewallRule"
                }
            }
            else {
                outputText "    *************** WARNING - No firewall rules, accessible to the entire internet ***************"
            }
        }

    }

}

function verifyPublicContainers($SubscriptionId,$headerParams) { 
    $publicContainers=@()
    $url = "https://management.azure.com/subscriptions/${SubscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01"
    $storageAccounts = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get

    foreach ($storageAccount in $storageAccounts.value) {
        $storageAccountName = $storageAccount.name
        $storageAccountId = $storageAccount.id
        $resourceGroup = $storageAccountId.split('/')[4]

        $url = "https://management.azure.com/${storageAccountId}/blobServices/default/containers?api-version=2018-03-01-preview"
        $containers = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get
        foreach($container in $containers.value) {
            if ($container.properties.publicAccess -ne "None") {
                $firewallRules = @()
                $url="https://management.azure.com/${storageAccountId}?api-version=2019-06-01"
                $storageAccountDetails = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get
                foreach($networkAclIpRule in $storageAccountDetails.properties.networkAcls.ipRules) {
                    $rule = "source IP: $($networkAclIpRule.value), action: $($networkAclIpRule.action)"
                    $firewallRules += $rule
                }
                foreach($virtualNetworkRule in $storageAccountDetails.properties.networkAcls.virtualNetworkRules) {
                    $rule = "Vnet service endpoint access: $($virtualNetworkRule.id)"
                    $firewallRules += $rule
                }   
                $publicContainerDetails = "ResourceGroup name: $resourceGroup, StorageAccount name: $storageAccountName, Container name: $($container.name)"
                $publicContainers += @{
                                    publicContainerDetails = $publicContainerDetails
                                    firewallAllowedIPsAndVnetSubnets = $firewallRules
                                    }
            }
        }
    }
    return $publicContainers
}
    

$headerParams = @{}
# Get the access token either from the Runbook service principal or the registered app service principal
if (($useRunbookRunAsAccount -ieq 'true') -or ($useRunbookRunAsAccount -eq '1')  -or ($useRunbookRunAsAccount -ieq 'yes')) {

    $connection = Get-AutomationConnection -Name AzureRunAsConnection

    $loginResult = Connect-AzureRmAccount -ServicePrincipal -Tenant $connection.TenantID `
    -ApplicationID $connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint

    $context = Get-AzureRmContext
    $cache = $context.TokenCache
    $cacheItem = $cache.ReadItems()
    $accessToken=$cacheItem[$cacheItem.Count -1].AccessToken

    $headerParams.Add('Authorization',"Bearer $accessToken")

} 
else {

    $remoteTenantCredential = Get-AutomationPSCredential -Name $readerAccountCredentialName
    $url = "https://login.windows.net/$tenantOrganizationName/.well-known/openid-configuration"
    $openIdConfig = Invoke-RestMethod -Uri $url -Method Get

    $clientId = $remoteTenantCredential.UserName
    $clientSecret = $remoteTenantCredential.GetNetworkCredential().Password
    $resource = "https://management.core.windows.net/"
    $requestAccessTokenUri = $openIdConfig.token_endpoint
    $body = "grant_type=client_credentials&client_id=$clientId&client_secret=$clientSecret&resource=$resource"

    $token = Invoke-RestMethod -Method Post -Uri $requestAccessTokenUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $headerParams.Add("Authorization","$($token.token_type) "+ " " + "$($token.access_token)")
}

$blueprintPolicyDefinitionIds = @()
$blueprintPolicySetDefinitionIds = @()
$policyDisplayNameMapping = @{}

# Get the list of policy definitions from the Git repo

Invoke-WebRequest -Uri $repoUrl -OutFile $policyDefinitionsZippedPath

Unzip $policyDefinitionsZippedPath $policyDefinitionsUnzippedPath

$policyDefinitionIdsJson = Get-Content -Raw -Path $policyArtifactListFilePath | ConvertFrom-Json

foreach ($policyDefinition in $policyDefinitionIdsJson.policyDefinitions) {
    if ($policyDefinition.policyDefinitionId -like "*policySetDefinitions*") {
        $blueprintPolicySetDefinitionIds += $policyDefinition.policyDefinitionId
    }
    else {
        $blueprintPolicyDefinitionIds += $policyDefinition.policyDefinitionId
    }
}

# $localTenantHeaderParams = @{'Authorization'="Bearer $localTenantAccessToken"}

# $PBMMBlueprintNames = @($PBMMBlueprintName,$PBMMBlueprintExtensionsName)

# foreach ($PBMMBlueprintName in $PBMMBlueprintNames) {
#
#    $url="https://management.azure.com/subscriptions/$localSubscriptionId/providers/Microsoft.Blueprint/blueprints/$PBMMBlueprintName/artifacts?api-version=2018-11-01-preview"
#    $blueprintArtifacts = Invoke-RestMethod -Uri $url -Headers $localTenantHeaderParams -Method Get
#
#    # Extract the list of policy definition ids and policy set definition ids from the PBMM blueprint
#
#    foreach ($artifact in $blueprintArtifacts.value) {
#        if ($artifact.properties.policyDefinitionId -like '*policySetDefinition*') {
#            $blueprintPolicySetDefinitionIds += $artifact.properties.policyDefinitionId
#        }
#        else {
#            $blueprintPolicyDefinitionIds += $artifact.properties.policyDefinitionId
#        }
#        $policyDisplayNameMapping[$artifact.properties.policyDefinitionId] = $artifact.properties.displayName
#    }
#
#}

# Get the list of all subscriptions in the target tenant
$url = "https://management.azure.com/subscriptions?api-version=2019-06-01"
$subscriptionsJson = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get

$subscriptions = $subscriptionsJson.value

$targetSubscriptionId = $subscriptions[0].subscriptionId

# Get the list of policies associated with each policy set and add to the list of blueprint policies

$url = "https://management.azure.com/subscriptions/$targetSubscriptionId/providers/Microsoft.Authorization/policySetDefinitions?api-version=2018-05-01" 
$policySetDefinitions = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get

$blueprintExpandedPolicyDefinitionIds = $blueprintPolicyDefinitionIds
foreach ($policyDefinitionName in $blueprintPolicySetDefinitionIds) {
    if ($policyDefinitionName -like '*policySetDefinition*') {
        foreach ($policySetDefinition in $policySetDefinitions.value) {
            if ($policySetDefinition.id -eq $policyDefinitionName) {
                foreach ($policy in $policySetDefinition.properties.policyDefinitions) {
                    $blueprintExpandedPolicyDefinitionIds += $policy.policyDefinitionId
                }
            }
        }
    }
}

# Get the display names for all policy definitions

$url = "https://management.azure.com/subscriptions/$targetSubscriptionId/providers/Microsoft.Authorization/policyDefinitions?api-version=2018-05-01"
$policyDefinitions = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get

foreach($policyDefinition in $policyDefinitions.value) {
    $policyDisplayNameMapping[$policyDefinition.id] = $policyDefinition.properties.displayName
}

$url = "https://management.azure.com/subscriptions/$targetSubscriptionId/providers/Microsoft.Authorization/policySetDefinitions?api-version=2018-05-01"
$policySetDefinitions = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get

foreach($policySetDefinition in $policySetDefinitions.value) {
    $policyDisplayNameMapping[$policySetDefinition.id] = $policySetDefinition.properties.displayName
}

$subscriptionComplianceResults = @()

# Get a list of all subscriptions in the target tenant

foreach ($subscription in $subscriptions) {
    $complianceResultsSummary = @{}
    $SubscriptionId = $subscription.subscriptionId


    $complianceResultsSummary.subscriptionId = $SubscriptionId
    $complianceResultsSummary.numMissingPolicies = 0
    $complianceResultsSummary.numNonCompliantResources = 0
    $complianceResultsSummary.hasPolicyExclusions = $false
    $complianceResultsSummary.numSubnetsWithDirectInternetAccess = 0
    $complianceResultsSummary.numSubnetsWithDirectRouteToInternetUnauthorized = 0
    $complianceResultsSummary.numSubnetsWithDirectRouteToInternetAuthorized = 0
    $complianceResultsSummary.numNetworkInterfacesWithPublicIPUnauthorized = 0
    $complianceResultsSummary.numNetworkInterfacesWithPublicIPAuthorized = 0
    $complianceResultsSummary.nonCompliantResources = @()
    $complianceResultsSummary.missingPolicies = @()
    $complianceResultsSummary.authorizedSubnetsWithDirectRouteToInternet = @()
    $complianceResultsSummary.unauthorizedSubnetsWithDirectRouteToInternet = @()
    $complianceResultsSummary.authorizedNetworkInterfacesWithPublicIPs = @()
    $complianceResultsSummary.unauthorizedNetworkInterfacesWithPublicIPs = @()
    $complianceResultsSummary.policyScopeExclusions = @()
    $complianceResultsSummary.publicStorageAccountContainers = @()

    # Get the list of policy assignments for the current subscription
    # TODO handle management group level blueprint assignment scenario

    $url="https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/policyAssignments?api-version=2018-05-01"
    $policyAssignments = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get

    $policyDefinitionIdToAssignmentMapping = @{}
    $policyAssignmentExclusions = @{}
    foreach ($assignment in $policyAssignments.value) {

        $policyDefinitionIdToAssignmentMapping.add($assignment.properties.policyDefinitionId,$assignment.id)
        $policyAssignmentExclusions[$assignment.id] = $assignment.properties.notScopes
    }


    # verify that all policies and policy set (initiatives) in the PBMM blueprint have assignments in the current subscription

    foreach ($policyDefinitionId in $blueprintPolicyDefinitionIds) {
        if (-not $policyDefinitionIdToAssignmentMapping.ContainsKey($policyDefinitionId)) {
            $policyDefinitionDisplayName = $policyDisplayNameMapping[$policyDefinitionId]
            $complianceResultsSummary.numMissingPolicies += 1
            $missingPolicy = @{
                                policyDefinitionId = $policyDefinitionId;
                                policyDefinitionDisplayName = $policyDefinitionDisplayName
                            }
            $complianceResultsSummary.missingPolicies += $missingPolicy
        }
    }

    foreach ($policySetDefinitionId in $blueprintPolicySetDefinitionIds) {
        if (-not $policyDefinitionIdToAssignmentMapping.ContainsKey($policySetDefinitionId)) {
            $policySetDefinitionDisplayName = $policyDisplayNameMapping[$policySetDefinitionId]
            $complianceResultsSummary.numMissingPolicies += 1
            $missingPolicy = @{
                                policyDefinitionId = $policySetDefinitionId
                                policyDefinitionDisplayName = $policySetDefinitionDisplayName
                            }
            $complianceResultsSummary.missingPolicies += $missingPolicy
        }
    }


    # Get the summary state of all policy assignments in the current subscription

    $url = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2018-04-04"
    $policyStateSummary = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Post

    $policyAssignmentComplianceResults = @{}
    foreach ($assignment in $policyStateSummary.value.policyAssignments) {
        $complianceResults = @{
                                nonCompliantResourceCount = $assignment.results.nonCompliantResources;
                            }
        $policyAssignmentComplianceResults[$assignment.policyAssignmentId] = $complianceResults
    }

    # Output the non-compliant resource count for each policy assignment

    $totalNonCompliantResources = 0
    $blueprintPolicyAndPolicySetDefinitions = $blueprintPolicyDefinitionIds + $blueprintPolicySetDefinitionIds
    foreach ($policyDefinition in $blueprintPolicyAndPolicySetDefinitions) {
        $policyAssignment = $policyDefinitionIdToAssignmentMapping[$policyDefinition]
        if ($policyAssignment -ne $null) {
            $policyDisplayName = $policyDisplayNameMapping[$policyDefinition]
            $policyExclusions = $policyAssignmentExclusions[$policyAssignment]
            if ($policyAssignmentComplianceResults.ContainsKey($policyAssignment)) {
                $nonCompliantResourceCount = $policyAssignmentComplianceResults[$policyAssignment].nonCompliantResourceCount
                $totalNonCompliantResources += $nonCompliantResourceCount

            }
            else {    
            }
            if ($policyExclusions.Count -gt 0) {
                $policyScopeExclusions = @()
                foreach ($exclusionScope in $policyExclusions) {
                    $policyScopeExclusions += $exclusionScope
                }
                $complianceResultsSummary.hasPolicyExclusions = $true
                $policyExclusionsEntry = @{
                                        policyDefinitionId = $policyDefinition;
                                        policyDisplayName = $policyDisplayName;
                                        scopeExclusions = $policyScopeExclusions
                                    }
                $complianceResultsSummary.policyScopeExclusions += $policyExclusionsEntry
            }
        }
    }

    $complianceResultsSummary.numNonCompliantResources = $totalNonCompliantResources
 
    # Get the latest policy state for each policy definition and display non-compliant resources

    foreach ($policyDefinitionId in $blueprintExpandedPolicyDefinitionIds) {
        $splitPolicyDefinitionId = $policyDefinitionId -split '/'
        $policyDefinitionName = $splitPolicyDefinitionId[-1]
        $policyDisplayName = $policyDisplayNameMapping[$policyDefinitionId]

        $url = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2018-04-04&%24filter=(policyDefinitionName%20eq%20%27${policyDefinitionName}%27)"
        $policyStates = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Post
        if ($policyStates.value.Count -gt 0) {
            $nonCompliantResources = @{}
            foreach ($policyState in $policyStates.value) {
                $resourceId = $policyState.resourceId
                $nonCompliantResources[$resourceId] = "Not used"
            }
            $nonCompliantResourcesSummary = @{
                            policyDefinitionId = $policyDefinitionId;
                            policyDisplayName = $policyDisplayName;
                            nonCompliantResources = $nonCompliantResources.Keys
                        }
            $complianceResultsSummary.nonCompliantResources += $nonCompliantResourcesSummary
        }

    }

    # List all subnets that have direct access to the internet

    $url = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Network/virtualNetworks?api-version=2019-07-01"
    $vnets = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get

    $subnetsWithDirectRouteToInternetUnauthorized = @()
    $subnetsWithDirectRouteToInternetAuthorized = @()

    foreach ($vnet in $vnets.value) {
        $subnetPolicyExceptions = @{}
        $sandboxResource = $false
        if ($vnet.tags -ne $null) {

            if ($vnet.tags.policyExceptions -ne $null) {
                $policyExceptions = $vnet.tags.policyExceptions
                $json = $vnet.tags.policyExceptions | ConvertFrom-Json
                foreach ($property in $json.PSObject.Properties) {
                    $key = $property.Name.Trim()
                    $subnetPolicyExceptions[$key] = $property.Value.Split(",").Trim()
                }
            }
            if ($vnet.tags.CloudUsageProfile -ne $null) {
                if (($vnet.tags.CloudUsageProfile -ieq 'profile1') -or ($vnet.tags.CloudUsageProfile -ieq 'profile2')) {
                    $sandboxResource = $true
                }
            }
        }
        if (-Not $sandboxResource) {
            $resourceGroupName = $vnet.id.split("/")[4]
            $url = "https://management.azure.com/subscriptions/$SubscriptionId/resourcegroups/${resourceGroupName}?api-version=2019-08-01"
            $resourceGroup = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get
            $tags = $resourceGroup.tags
            if ($tags.CloudUsageProfile -ne $null) {
                if (($tags.CloudUsageProfile -ieq 'profile1') -or ($tags.CloudUsageProfile -ieq 'profile2')) {
                    $sandboxResource = $true
                }
            }
        }

        foreach ($subnet in $vnet.properties.subnets) {
            $routeToInternetAuthorized = $false
            $subnetName = $subnet.name
            if ((($subnetPolicyExceptions.ContainsKey($subnetName)) -and ($subnetPolicyExceptions[$subnetName].Contains("directRouteToInternetAllowed")) -or `
                ($sandboxResource)) -or `
                (($subnetPolicyExceptions.ContainsKey("*")) -and ($subnetPolicyExceptions['*'] -eq "directRouteToInternetAllowed")))
            {
                $routeToInternetAuthorized = $true
            }

            if ($subnet.properties.routeTable -eq $null) {
                # The subnet is using the default route table which includes a route to the internet 
                $complianceResultsSummary.numSubnetsWithDirectInternetAccess += 1
                if ($routeToInternetAuthorized) {
                    $subnetsWithDirectRouteToInternetAuthorized += $subnet.id
                }
                else {
                    $subnetsWithDirectRouteToInternetUnauthorized += $subnet.id
                }    
            }
            else {
                $routeTableId = $subnet.properties.routeTable.id
                $splitRouteTableId = $routeTableId.split('/')
                $routeTableName = $splitRouteTableId[-1]
                $routeTableRG = $splitRouteTableId[4]

                $url = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$routeTableRG/providers/Microsoft.Network/routeTables/${routeTableName}?api-version=2019-07-01"
                $routeTable = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get

                foreach ($route in $routeTable.properties.routes) {
                    if ($route.properties.nextHopType -eq "Internet") {
                        $complianceResultsSummary.numSubnetsWithDirectInternetAccess += 1
                        if ($routeToInternetAuthorized) {
                            $subnetsWithDirectRouteToInternetAuthorized += $subnet.id
                        }
                        else {
                            $subnetsWithDirectRouteToInternetUnauthorized += $subnet.id
                        }    
                    }
                }
            }
        }

    }

    if ($subnetsWithDirectRouteToInternetAuthorized.Count -gt 0) {
        foreach($subnet in $subnetsWithDirectRouteToInternetAuthorized) {
            $complianceResultsSummary.authorizedSubnetsWithDirectRouteToInternet += $subnet
        }
    }


    if ($subnetsWithDirectRouteToInternetUnauthorized.Count -gt 0) {
        foreach($subnet in $subnetsWithDirectRouteToInternetUnauthorized) {
            $complianceResultsSummary.unauthorizedSubnetsWithDirectRouteToInternet += $subnet
        }
    }

    $complianceResultsSummary.numSubnetsWithDirectRouteToInternetUnauthorized = $subnetsWithDirectRouteToInternetUnauthorized.Count
    $complianceResultsSummary.numSubnetsWithDirectRouteToInternetAuthorized = $subnetsWithDirectRouteToInternetAuthorized.Count


    # List all network interfaces that have public IPs

    $url = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Network/networkInterfaces?api-version=2019-07-01"
    $networkInterfaces = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get

    $networkInterfacesWithPublicIPsUnauthorized = @()
    $networkInterfacesWithPublicIPsAuthorized = @()

    foreach ($networkInterface in $networkInterfaces.value) {
        $policyExceptions = @()
        $CloudUsageProfile = $null
        if ($networkInterface.tags -ne $null) {
            if ($networkInterface.tags.policyExceptions -ne $null) {
                $policyExceptions = $networkInterface.tags.policyExceptions.Split(",").Trim()
            }
            if ($networkInterface.tags.CloudUsageProfile -ne $null) {
                $CloudUsageProfile = $networkInterface.tags.CloudUsageProfile.Trim()
            }
        }
        if ($CloudUsageProfile -eq $null) {
            $resourceGroupName = $networkInterface.id.split("/")[4]
            $url = "https://management.azure.com/subscriptions/$SubscriptionId/resourcegroups/${resourceGroupName}?api-version=2019-08-01"
            $resourceGroup = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get
            $tags = $resourceGroup.tags
            if ($tags.CloudUsageProfile -ne $null) {
                $CloudUsageProfile = $tags.CloudUsageProfile.Trim()
            }
        }

        if ($policyExceptions.Count -eq 0) {
            $resourceGroupName = $networkInterface.id.split("/")[4]
            $url = "https://management.azure.com/subscriptions/$SubscriptionId/resourcegroups/${resourceGroupName}?api-version=2019-08-01"
            $resourceGroup = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Get
            $tags = $resourceGroup.tags
            if ($tags.policyExceptions -ne $null) {
                $policyExceptions = $tags.policyExceptions.Split(",").Trim()
            }
        }

        if ($networkInterface.properties.ipConfigurations.properties.publicIPAddress -ne $null) {
            if ((($policyExceptions.Contains("publicIPAllowed")) -or ($CloudUsageProfile -ieq 'profile1')) -or ($CloudUsageProfile -ieq 'profile2')) {
                $networkInterfacesWithPublicIPsAuthorized += $networkInterface.id
            }
            else {
                $networkInterfacesWithPublicIPsUnauthorized += $networkInterface.id                
            }
        }
    }

    if ($networkInterfacesWithPublicIPsAuthorized.Count -gt 0) {
        foreach($networkInterface in $networkInterfacesWithPublicIPsAuthorized) {
            $complianceResultsSummary.authorizedNetworkInterfacesWithPublicIPs += $networkInterface
        }
    }

    if ($networkInterfacesWithPublicIPsUnauthorized.Count -gt 0) {
        foreach($networkInterface in $networkInterfacesWithPublicIPsUnauthorized) {
            $complianceResultsSummary.unauthorizedNetworkInterfacesWithPublicIPs += $networkInterface
        }
    }


    $complianceResultsSummary.numNetworkInterfacesWithPublicIPUnauthorized = $networkInterfacesWithPublicIPsUnauthorized.Count
    $complianceResultsSummary.numNetworkInterfacesWithPublicIPAuthorized = $networkInterfacesWithPublicIPsAuthorized.Count

    $complianceResultsSummary.publicStorageAccountContainers = verifyPublicContainers $SubscriptionId $headerParams

    $subscriptionComplianceResults += $complianceResultsSummary

}

# Output compliance results to a JSON file and copy to blob storage

$results = @{
                tenantId = $subscriptions[0].tenantId;
                tenantOrgName = $tenantOrganizationName;
                results = $subscriptionComplianceResults
            }


$results | ConvertTo-Json -depth 100 | Out-File $complianceVerificationResultsFilePath -Encoding "UTF8"

# Login using the automation account's local runAs service principal

$connection = Get-AutomationConnection -Name AzureRunAsConnection

Connect-AzureRmAccount -ServicePrincipal -Tenant $connection.TenantID `
                -ApplicationID $connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint

$storageAccountKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $resultsStorageAccountResourceGroupName -AccountName $resultsStorageAccountName).value[0]

$context = New-AzureStorageContext -StorageAccountName $resultsStorageAccountName -StorageAccountKey $storageAccountKey

$fileUploadResult = Set-AzureStorageBlobContent -File $complianceVerificationResultsFilePath -Container $resultsContainerName -Blob $complianceVerificationResultsFileName -Context $context -Properties @{"ContentEncoding" = "UTF-8"} -Force

outputComplianceResultAsText $subscriptionComplianceResults

$fileUploadResult = Set-AzureStorageBlobContent -File $complianceVerificationResultsTextFilePath -Container $resultsContainerName -Blob $complianceVerificationResultTextFileName -Context $context -Properties @{"ContentEncoding" = "UTF-8"} -Force

