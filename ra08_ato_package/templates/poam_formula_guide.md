# POA&M Formula Guidance

- Days Open = TODAY() - Date Identified
- SLA (Days) = IF(Severity in Critical/High, 30, IF(Severity = Medium, 90, 180))
- Days Remaining = Scheduled Completion Date - TODAY()
- Overdue = IF(TODAY() > Scheduled Completion Date, "Yes", "No")
