$ErrorActionPreference = "Stop"

# ----------------------- Configurable settings start ------------------------------

# ----------------------- Configurable settings end ------------------------------

# Remove hard coding later
$blueprintEnvironmentFolder = "pbmm-profile-6"
$blueprintTypeFolder = "30-day-guardrails"

$tempFilePath = $env:TEMP
$blueprintDefinitionsPathPrefix = "cloud-guardrails-azure-master\toolbox"
$blueprintDefinitionFolderName = "gc-guardrail-blueprint-definitions"
$policyDefinitionsZippedPath = "$tempFilePath\PBMMComplianceVerification.zip"
$policyDefinitionsUnzippedPath = "$tempFilePath\PBMM-Compliance-Verification"
$mainBlueprintDefinitionFileName = "main-blueprint-definition.json"
$policyArtifactsFileName = "policy-artifact-list.json"
$policyArtifactDefinitionsFolderName = "policy-artifact-definitions"
$allPoliciesFileName = "all-policies.json"
$repoUrl = "https://github.com/tacummins1/testtbsrepo/archive/master.zip"

$mainBlueprintDefinitionFilePath = "$policyDefinitionsUnzippedPath\$blueprintDefinitionsPathPrefix\$blueprintDefinitionFolderName\$blueprintEnvironmentFolder\$blueprintTypeFolder\$mainBlueprintDefinitionFileName"
$policyArtifactListFilePath = "$policyDefinitionsUnzippedPath\$blueprintDefinitionsPathPrefix\$blueprintDefinitionFolderName\$blueprintEnvironmentFolder\$blueprintTypeFolder\$policyArtifactsFileName"
$policyArtifactDefinitionsPath = "$policyDefinitionsUnzippedPath\$blueprintDefinitionsPathPrefix\$blueprintDefinitionFolderName\$policyArtifactDefinitionsFolderName"
$allPoliciesListFilePath = "$policyDefinitionsUnzippedPath\$blueprintDefinitionsPathPrefix\$blueprintDefinitionFolderName\$allPoliciesFileName"

# Connect using the automation account's Run As service principal

$connection = Get-AutomationConnection -Name AzureRunAsConnection

$loginResult = Connect-AzureRmAccount -ServicePrincipal -Tenant $connection.TenantID `
-ApplicationID $connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint

$context = Get-AzureRmContext
$subscriptionId = $context.Subscription
$cache = $context.TokenCache
$cacheItem = $cache.ReadItems()
$accessToken=$cacheItem[$cacheItem.Count -1].AccessToken

$headerParams = @{'Authorization'="Bearer $accessToken";'Content-Type'="application/json"}

$tempFilePath = $env:TEMP
$policyDefinitionsZippedPath = "$tempFilePath\PBMMPolicyDefinitions.zip"
$policyDefinitionsUnzippedPath = "$tempFilePath\PBMM-Compliance-Verification"

$policyDefinitionsBaselineFilePath = "$policyDefinitionsUnzippedPath\$policyDefinitionFilesPath\$baselinePolicyDefinitionsFileName"
$policyDefinitionsExtensionsFilePath = "$policyDefinitionsUnzippedPath\$policyDefinitionFilesPath\$extensionsPolicyDefinitionsFileName"

Add-Type -AssemblyName System.IO.Compression.FileSystem

# Unzip function
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    Remove-Item -Path $outpath -Recurse -ErrorAction Ignore
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}

function ExcludeResourcesFromPolicyAssignment($policyAssignment, $resourceIds) {
    $policyDefinitionId = $policyAssignment.properties.policyDefinitionId 
    
    $notScopes = @{}
    foreach ($notScope in $policyAssignment.properties.notScopes) {
        $notScopes[$notScope] = "notUsed"
    }
    foreach ($resourceId in $resourceIds) {
        $notScopes[$resourceId] = "notUsed"
    }
    
    $policyAssignment.properties.notScopes = $notScopes.keys
    $policyAssignmentName = $policyAssignment.name

    $policyAssignmentJson = ConvertTo-Json $policyAssignment -Depth 100

    $resourceCount = $resourceIds.Count
    Write-Output "Excluding ${resourceCount} resources from ${policyDefinitionId}:"
    

    $url = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Authorization/policyAssignments/${policyAssignmentName}?api-version=2018-05-01"
    $ignore = Invoke-RestMethod -Uri $url -Method Put -Headers $headerParams -Body $policyAssignmentJson

}

# Get the list of policy definitions from the Git repo

#Write-Output "Making REST API call"
Invoke-WebRequest -Uri $repoUrl -OutFile $policyDefinitionsZippedPath

#Write-Output "REST API call succeeded"
Unzip $policyDefinitionsZippedPath $policyDefinitionsUnzippedPath

# Get the list of policy artifacts for the cloud usage profile

$policyArtifacts = Get-Content -Raw -Path $policyArtifactListFilePath | ConvertFrom-Json
$blueprintPolicyDefinitionIds = @()

foreach ($policyDefinition in $policyArtifacts.policyDefinitions) {
    $blueprintPolicyDefinitionIds += $policyDefinition.policyDefinitionId
}

# Get the list of all policies for GC guardrails

$allPolicies = Get-Content -Raw -Path $allPoliciesListFilePath | ConvertFrom-Json
Write-Output "Got all policies"

$allPolicyDefinitionIds = @()
foreach($policy in $allPolicies.policyDefinitions) {
    $allPolicyDefinitionIds += $policy.policyDefinitionId
}

# Get all resources tagged as sandbox (profile 1) and exclude from all policy assignment scopes
# TODO change to only exclude those policies that are not included in profile 1

$sandboxResourceIds = @()
$resourceGroups = Get-AzureRmResourceGroup -Tag @{cloudUsageProfile="profile1"}

$resources = Get-AzureRmResource -Tag @{cloudUsageProfile="profile1"}

foreach ($resourceGroup in $resourceGroups) {
    $sandboxResourceIds += $resourceGroup.ResourceId
}

foreach ($resource in $resources) {
    $sandboxResourceIds += $resource.ResourceId
}


# For all resources and resource groups tagged with cloudUsageProfile with a value of profile1 (sandbox),
# add to policy assignment scope exclusion list.

$url = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Authorization/policyAssignments?api-version=2018-05-01"
$policyAssignmentsJson = Invoke-RestMethod -Uri $url -Method Get -Headers $headerParams
$policyDefinitionIdToAssignmentMapping = @{}
foreach ($policyAssignment in $policyAssignmentsJson.value) {
    $policyDefinitionId = $policyAssignment.properties.policyDefinitionId 
    $policyDefinitionIdToAssignmentMapping[$policyDefinitionId] = $policyAssignment
    if ($allPolicyDefinitionIds -contains $policyDefinitionId) {
        # Write-Output "About to exclude resources from ${policyDefinitionId}:"
        # $sandboxResourceIds
        ExcludeResourcesFromPolicyAssignment $policyAssignment $sandboxResourceIds
    }
}

# Go through all guardrail policies and for each policy that has a policy exception tag value,
# get all resources and resource groups tagged with that policy exception tag value.

foreach($policy in $allPolicies.policyDefinitions) {
    if ($policy.policyExceptionTagValue -ne $null) {
        $tagValue = $policy.policyExceptionTagValue

        $resourceIds = @()
        $resourceGroups = Get-AzureRmResourceGroup

        $resources = Get-AzureRmResource -TagName "policyExceptions"

        Write-Output "Tag value: ${tagValue}"

        foreach ($resourceGroup in $resourceGroups) {
            if ($resourceGroup.Tags.policyExceptions -ne $null) {
                $policyExceptions = $resourceGroup.Tags.policyExceptions.split(",").trim()
                if ($policyExceptions -contains $tagValue) {
                    $resourceIds += $resourceGroup.ResourceId
                }
            }
        }

        foreach ($resource in $resources) {
            $policyExceptions = $resource.Tags.policyExceptions.split(",").trim()
            if ($policyExceptions -contains $tagValue) {
                $resourceIds += $resource.ResourceId
            }
        }

        if ($resourceIds.Count -gt 0) {
            $policyAssignment = $policyDefinitionIdToAssignmentMapping[$policy.policyDefinitionId]
            $policyAssignment
            ExcludeResourcesFromPolicyAssignment $policyAssignment $resourceIds
        }
        
    }
} 


