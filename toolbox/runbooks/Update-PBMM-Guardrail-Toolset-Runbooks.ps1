Param
(
    [Parameter (Mandatory= $true)]
    [String] $automationAccountName,   

    [Parameter (Mandatory= $true)]
    [String] $automationAccountRGName
)

$ErrorActionPreference = "Stop"

# ----------------------- Configurable settings start ------------------------------

# ----------------------- Configurable settings end ------------------------------

$tempFilePath = $env:TEMP
$blueprintDefinitionsPathPrefix = "cloud-guardrails-azure-master\toolbox"
$policyDefinitionsZippedPath = "$tempFilePath\PBMMComplianceVerification.zip"
$policyDefinitionsUnzippedPath = "$tempFilePath\PBMM-Compliance-Verification"
$repoUrl = "https://github.com/canada-ca/cloud-guardrails-azure/archive/master.zip"

$runbooksFolderName = "runbooks"
$runbooksFolderPath = "$policyDefinitionsUnzippedPath\$blueprintDefinitionsPathPrefix\$runbooksFolderName"


# Connect using the automation account's Run As service principal

$connection = Get-AutomationConnection -Name AzureRunAsConnection

Connect-AzureRmAccount -ServicePrincipal -Tenant $connection.TenantID `
                -ApplicationID $connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint

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

$runbookFilenames = Get-ChildItem -Path $runbooksFolderPath -Name

foreach($fileName in $runbookFilenames) {

    # Skip importing this runbook
    Write-Output $filename
    
    if ($filename -ne "Update-PBMM-Guardrail-Toolset-Runbooks.ps1") {
        $runbookFilePath = $runbooksFolderPath + "\" + $fileName

        $runbookName = ($fileName.split("."))[0]

        Import-AzureRMAutomationRunbook -Name $runbookName -Path $runbookFilePath `
        -ResourceGroupName $automationAccountRGName -AutomationAccountName $automationAccountName `
        -Type PowerShell -Force
    }
}



