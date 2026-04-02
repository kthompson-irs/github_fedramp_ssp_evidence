# Power BI Data Model + Measures Pack

## Recommended Tables

### Fact Tables
- fact_control_status
- fact_evidence_event
- fact_findings
- fact_poam_items
- fact_ingest_health

### Dimension Tables
- dim_control
- dim_control_family
- dim_system
- dim_source
- dim_severity
- dim_owner
- dim_date

## Suggested Relationships
- dim_control[control_id] -> fact_control_status[control_id]
- dim_control[control_id] -> fact_evidence_event[control_id]
- dim_control[control_id] -> fact_findings[control_id]
- dim_control[control_id] -> fact_poam_items[control_id]
- dim_control_family[control_family] -> fact_control_status[control_family]
- dim_control_family[control_family] -> fact_findings[control_family]
- dim_system[system_name] -> fact_control_status[system_name]
- dim_system[system_name] -> fact_findings[system_name]
- dim_owner[owner_name] -> fact_findings[owner]
- dim_date[date] -> fact tables after date cast

## Core Measures (DAX)

```DAX
Compliance Score =
DIVIDE(
    CALCULATE(COUNTROWS(fact_control_status), fact_control_status[status] = "PASS"),
    COUNTROWS(fact_control_status)
)
```

```DAX
Passed Controls =
CALCULATE(
    COUNTROWS(fact_control_status),
    fact_control_status[status] = "PASS"
)
```

```DAX
Failed Controls =
CALCULATE(
    COUNTROWS(fact_control_status),
    fact_control_status[status] = "FAIL"
)
```

```DAX
Warning Controls =
CALCULATE(
    COUNTROWS(fact_control_status),
    fact_control_status[status] = "WARNING"
)
```

```DAX
Unknown Controls =
CALCULATE(
    COUNTROWS(fact_control_status),
    fact_control_status[status] = "UNKNOWN"
)
```

```DAX
Open Findings =
CALCULATE(
    COUNTROWS(fact_findings),
    fact_findings[status] <> "Closed"
)
```

```DAX
High Severity Findings =
CALCULATE(
    COUNTROWS(fact_findings),
    fact_findings[severity] IN {"High", "Critical"},
    fact_findings[status] <> "Closed"
)
```

```DAX
Open POA&M Items =
CALCULATE(
    COUNTROWS(fact_poam_items),
    fact_poam_items[status] <> "Closed"
)
```

```DAX
Evidence Freshness Hours =
DATEDIFF(
    MAX(fact_evidence_event[collected_at]),
    NOW(),
    HOUR
)
```

```DAX
Drift Events (Last 24h) =
CALCULATE(
    COUNTROWS(fact_control_status),
    fact_control_status[status] = "FAIL",
    fact_control_status[last_checked_at] >= NOW() - 1
)
```

```DAX
Ingest Lag Minutes =
MAX(fact_ingest_health[lag_minutes])
```

```DAX
Ingest Health Flag =
IF([Ingest Lag Minutes] > 60, "DEGRADED", "HEALTHY")
```

## Page Map
- Executive Summary
- Control Family Overview
- GitHub Compliance
- Cloud Compliance
- Evidence / POA&M

## Slicers
- Date range
- System
- Control family
- Severity
- Status
- Owner
- Source system
