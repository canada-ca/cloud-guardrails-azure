Param
(
    [Parameter (Mandatory= $true)]
    [String] $subscriptionId,   

    [Parameter (Mandatory= $true)]
    [String] $cloudUsageProfile
)

$ErrorActionPreference = "Stop"


# ----------------------- Configurable settings start ------------------------------

# ----------------------- Configurable settings end ------------------------------

# TODO update later to support all profiles

if ($cloudUsageProfile -eq "6") {
    $blueprintEnvironmentFolder = "pbmm-profile-6"
    $blueprintTypeFolder = "30-day-guardrails"
}

$tempFilePath = $env:TEMP
$blueprintDefinitionsPathPrefix = "testtbsrepo-master\test"
$blueprintDefinitionFolderName = "gc-guardrail-blueprint-definitions"
$policyDefinitionsZippedPath = "$tempFilePath\PBMMComplianceVerification.zip"
$policyDefinitionsUnzippedPath = "$tempFilePath\PBMM-Compliance-Verification"
$mainBlueprintDefinitionFileName = "main-blueprint-definition.json"
$policyArtifactsFileName = "policy-artifact-list.json"
$policyArtifactDefinitionsFolderName = "policy-artifact-definitions" 
$repoUrl = "https://github.com/tacummins1/testtbsrepo/archive/master.zip"

$mainBlueprintDefinitionFilePath = "$policyDefinitionsUnzippedPath\$blueprintDefinitionsPathPrefix\$blueprintDefinitionFolderName\$blueprintEnvironmentFolder\$blueprintTypeFolder\$mainBlueprintDefinitionFileName"
$policyArtifactListFilePath = "$policyDefinitionsUnzippedPath\$blueprintDefinitionsPathPrefix\$blueprintDefinitionFolderName\$blueprintEnvironmentFolder\$blueprintTypeFolder\$policyArtifactsFileName"
$policyArtifactDefinitionsPath = "$policyDefinitionsUnzippedPath\$blueprintDefinitionsPathPrefix\$blueprintDefinitionFolderName\$policyArtifactDefinitionsFolderName"

Add-Type -AssemblyName System.IO.Compression.FileSystem

# Unzip function
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    Remove-Item -Path $outpath -Recurse -ErrorAction Ignore
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}
# Get the list of policy definitions from the Git repo

#Write-Output "Making REST API call"
Invoke-WebRequest -Uri $repoUrl -OutFile $policyDefinitionsZippedPath

#Write-Output "REST API call succeeded"
Unzip $policyDefinitionsZippedPath $policyDefinitionsUnzippedPath

$mainBlueprintDefinitionsJson = Get-Content -Raw -Path $mainBlueprintDefinitionFilePath | ConvertFrom-Json

# Login using the automation account's local runAs service principal

$connection = Get-AutomationConnection -Name AzureRunAsConnection

$loginResult = Connect-AzureRmAccount -ServicePrincipal -Tenant $connection.TenantID `
-ApplicationID $connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint

$context = Get-AzureRmContext
$subscriptionId = $context.Subscription
$cache = $context.TokenCache
$cacheItem = $cache.ReadItems()
$tenantAccessToken=$cacheItem[$cacheItem.Count -1].AccessToken

$blueprintPolicyDefinitionIds = @()
$blueprintPolicySetDefinitionIds = @()
$policyDisplayNameMapping = @{}

# Get the list of policy artifacts that are included in the blueprint
$headerParams = @{'Authorization'="Bearer $tenantAccessToken"}
$blueprintName = $mainBlueprintDefinitionsJson.properties.displayName
$blueprintName = $blueprintName.replace(" ","-")
$url="https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Blueprint/blueprints/${blueprintName}?api-version=2018-11-01-preview"

$mainBlueprintDefinitionsJson = $mainBlueprintDefinitionsJson | ConvertTo-Json -Depth 100
$blueprintArtifacts = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Put -Body $mainBlueprintDefinitionsJson -ContentType "application/json"

$policyArtifacts = Get-Content -Raw -Path $policyArtifactListFilePath | ConvertFrom-Json
$blueprintPolicyDefinitionIds = @()

foreach ($policyDefinition in $policyArtifacts.policyDefinitions) {
    if ($policyDefinition.policyDefinitionId -like "*policySetDefinitions*") {
        $blueprintPolicyDefinitionIds += $policyDefinition.policyDefinitionId.split('/')[-1]
    }
    else {
        $blueprintPolicyDefinitionIds += $policyDefinition.policyDefinitionId.split('/')[-1]
    }
}

# Add policy artifacts to the blueprint

foreach ($policyDefinitionId in $blueprintPolicyDefinitionIds) {
    $policyArtifactDefinitionFullPath = "$policyArtifactDefinitionsPath\${policyDefinitionId}.json"
    $policyArtifacts = Get-Content -Raw -Path $policyArtifactDefinitionFullPath | ConvertFrom-Json
    $artifactName = $policyArtifacts.properties.policyDefinitionId.split('/')[-1]
    $policyArtifacts = $policyArtifacts | ConvertTo-Json -Depth 100
    
    $url="https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Blueprint/blueprints/${blueprintName}/artifacts/${artifactName}?api-version=2018-11-01-preview"
    $blueprintArtifacts = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Put -Body $policyArtifacts -ContentType "application/json"
}

# Publish the blueprint

$versionId = "1.0"
$url="https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Blueprint/blueprints/$blueprintName/versions/${versionId}?api-version=2018-11-01-preview"
$blueprintArtifacts = Invoke-RestMethod -Uri $url -Headers $headerParams -Method Put -ContentType "application/json"

