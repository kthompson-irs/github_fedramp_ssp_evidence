# IA-11 Evidence Binder

## Folder / file structure

```text
IA-11_Evidence_Binder/
├── README.md
├── 00_control_summary/
│   ├── IA-11_Control_Narrative.md
│   └── Control_to_Evidence_Matrix.xlsx
├── 01_policy/
│   ├── Access_Control_Policy.pdf
│   ├── Authentication_Policy.pdf
│   └── Session_Management_Standard.pdf
├── 02_aws_govcloud/
│   ├── aws_identity_center_permission_set.json
│   ├── aws_identity_center_session_duration.txt
│   ├── aws_iam_role_max_session_duration.json
│   ├── cloudtrail_consolelogin_events.json
│   ├── cloudtrail_lookup_query.txt
│   └── screenshots/
│       ├── aws_identity_center_session_duration.png
│       └── aws_role_max_session_duration.png
├── 03_azure_government/
│   ├── conditional_access_policies.json
│   ├── signin_logs.csv
│   ├── graph_queries.ps1
│   ├── graph_query_output.txt
│   └── screenshots/
│       ├── entra_signin_frequency_policy.png
│       └── entra_signin_logs.png
├── 04_test_demonstration/
│   ├── ia11_timeout_test_plan.md
│   ├── ia11_timeout_test_results.md
│   ├── ia11_timeout_test_screenshot_01.png
│   └── ia11_timeout_test_screenshot_02.png
└── 05_supporting_artifacts/
    ├── ticket_id_change_control.pdf
    ├── change_record_export.csv
    └── notes.md
```

## Evidence checklist

| Artifact | Purpose |
|---|---|
| SSP control narrative | Shows the approved control implementation statement |
| Policy documents | Show the governing requirement and session rules |
| AWS configuration exports | Show actual session duration and role duration values |
| AWS CloudTrail output | Shows sign-in and session activity |
| Azure conditional access export | Shows sign-in frequency or reauthentication policy |
| Azure sign-in logs export | Shows enforcement and usage evidence |
| Test results | Demonstrate the timeout and reauthentication behavior |
| Screenshots | Show the system state at the time of review |

## Naming standard
