#!/usr/bin/env bash
set -euo pipefail

# IA-11 evidence collection for AWS GovCloud
# Prereqs: awscli v2 configured for the target GovCloud account and region.

OUT_DIR="${1:-./aws_evidence}"
REGION="${AWS_REGION:-us-gov-west-1}"
mkdir -p "${OUT_DIR}"

# 1) Discover the IAM Identity Center instance.
aws sso-admin list-instances --region "${REGION}" --output json > "${OUT_DIR}/sso_instances.json"
INSTANCE_ARN=$(aws sso-admin list-instances --region "${REGION}" --query 'Instances[0].InstanceArn' --output text)
if [[ -z "${INSTANCE_ARN}" || "${INSTANCE_ARN}" == "None" ]]; then
  echo "No IAM Identity Center instance found in ${REGION}" >&2
  exit 1
fi

# 2) Export permission sets and session duration settings.
aws sso-admin list-permission-sets --instance-arn "${INSTANCE_ARN}" --region "${REGION}" --output json > "${OUT_DIR}/permission_sets.json"

python3 - <<'PY' "${OUT_DIR}" "${INSTANCE_ARN}" "${REGION}"
import json, subprocess, sys, os
out_dir, instance_arn, region = sys.argv[1:4]
with open(f"{out_dir}/permission_sets.json", "r", encoding="utf-8") as f:
    perm_sets = json.load(f).get("PermissionSets", [])
rows = []
for ps_arn in perm_sets:
    cmd = ["aws", "sso-admin", "describe-permission-set", "--instance-arn", instance_arn, "--permission-set-arn", ps_arn, "--region", region, "--output", "json"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    data = json.loads(res.stdout).get("PermissionSet", {})
    rows.append(data)
with open(f"{out_dir}/permission_set_details.json", "w", encoding="utf-8") as f:
    json.dump(rows, f, indent=2)
PY

# 3) Export IAM role max session duration. Provide ROLE_NAME as an env var or edit the script.
if [[ -n "${ROLE_NAME:-}" ]]; then
  aws iam get-role --role-name "${ROLE_NAME}" --region "${REGION}" --output json > "${OUT_DIR}/iam_role_${ROLE_NAME}.json"
fi

# 4) Export CloudTrail console sign-in events.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --region "${REGION}" \
  --output json > "${OUT_DIR}/cloudtrail_consolelogin_events.json"

# 5) Export a human-readable summary.
python3 - <<'PY' "${OUT_DIR}"
import json, os, sys
out_dir = sys.argv[1]
summary = []
with open(os.path.join(out_dir, "permission_set_details.json"), "r", encoding="utf-8") as f:
    for item in json.load(f):
        summary.append({
            "Name": item.get("Name"),
            "PermissionSetArn": item.get("PermissionSetArn"),
            "SessionDuration": item.get("SessionDuration")
        })
with open(os.path.join(out_dir, "aws_session_summary.json"), "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)
PY
