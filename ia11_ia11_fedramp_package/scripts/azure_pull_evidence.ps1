# Azure Government evidence collection wrapper
param(
    [string]$OutDir = ".\azure_evidence",
    [string]$StartDateUtc = "2026-03-01T00:00:00Z"
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Azure Government portal connection for any Azure control-plane evidence you want to capture separately.
# This uses the Azure Az PowerShell module.
Connect-AzAccount -Environment AzureUSGovernment | Out-Null
Get-AzContext | Format-List | Out-File -FilePath (Join-Path $OutDir "az_context.txt") -Encoding utf8
Get-AzLocation | Out-File -FilePath (Join-Path $OutDir "az_locations.txt") -Encoding utf8

# Microsoft Graph exports for Conditional Access and sign-in evidence.
& "$PSScriptRoot\azure_graph_queries.ps1" -OutDir $OutDir -StartDateUtc $StartDateUtc
