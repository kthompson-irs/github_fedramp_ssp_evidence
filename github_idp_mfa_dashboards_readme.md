# GitHub IdP MFA correlation assets

Files:
- github_idp_mfa_correlation.py
- github_idp_mfa_splunk_dashboard.json
- github_idp_mfa_sentinel_workbook.json

How to use:
1. Run the Python script against a GitHub audit-log export or GitHub API access plus an IdP export.
2. Use the Splunk JSON as a dashboard-spec starting point and update the index names and field names for your environment.
3. Use the Sentinel JSON as a workbook template and map the query to your workspace tables.

Notes:
- GitHub audit logs can be streamed to an external data management system, and the audit-log API can be used for retrieval.
- Microsoft Sentinel provides a GitHub audit log connector that can ingest logs into workbooks and custom alerts.
