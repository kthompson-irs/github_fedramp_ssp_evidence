# Microsoft Graph queries for Azure Government IA-11 evidence
# Prereqs: Microsoft.Graph PowerShell SDK installed.

param(
    [string]$OutDir = ".\azure_evidence",
    [string]$StartDateUtc = "2026-03-01T00:00:00Z",
    [string[]]$Scopes = @("Policy.Read.All", "AuditLog.Read.All")
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Connect to Microsoft Graph in the US Government cloud.
Connect-MgGraph -Environment USGov -Scopes $Scopes | Out-Null

# Export Conditional Access policies.
Get-MgIdentityConditionalAccessPolicy |
    ConvertTo-Json -Depth 20 |
    Out-File -FilePath (Join-Path $OutDir "conditional_access_policies.json") -Encoding utf8

# Export sign-in logs.
Get-MgAuditLogSignIn -All -Filter "createdDateTime ge $StartDateUtc" |
    Select-Object createdDateTime, userPrincipalName, appDisplayName, conditionalAccessStatus, ipAddress, clientAppUsed |
    Export-Csv -NoTypeInformation -Path (Join-Path $OutDir "signin_logs.csv")

# Save a context snapshot for audit trail.
Get-MgContext | Format-List | Out-File -FilePath (Join-Path $OutDir "graph_context.txt") -Encoding utf8

Disconnect-MgGraph | Out-Null
