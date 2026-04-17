#!/bin/bash
set -euo pipefail

curl -X POST "$SPLUNK_HEC_URL" \
  -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
  -H "Content-Type: application/json" \
  -d @ps04_report.json
