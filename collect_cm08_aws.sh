#!/usr/bin/env bash
set -euo pipefail

OUT_ROOT="${1:-cm08-aws-evidence-$(date -u +%Y%m%dT%H%M%SZ)}"
TMP_DIR="${OUT_ROOT}.tmp"
AWS_REGION_FALLBACK="${AWS_REGION:-us-east-1}"
RESOURCE_TYPES=(
  "AWS::EC2::Instance"
  "AWS::S3::Bucket"
  "AWS::IAM::Role"
  "AWS::IAM::User"
  "AWS::Lambda::Function"
  "AWS::RDS::DBInstance"
  "AWS::ECS::Cluster"
  "AWS::EKS::Cluster"
  "AWS::KMS::Key"
  "AWS::CloudFront::Distribution"
  "AWS::ElasticLoadBalancingV2::LoadBalancer"
  "AWS::ECR::Repository"
  "AWS::SecretsManager::Secret"
)

export AWS_PAGER=""
mkdir -p "$TMP_DIR"/config "$TMP_DIR"/tags "$TMP_DIR"/cloudtrail "$TMP_DIR"/securityhub "$TMP_DIR"/inspector "$TMP_DIR"/metadata "$TMP_DIR"/scripts

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$TMP_DIR/metadata/run.log"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

json_pretty() {
  if have_cmd jq; then
    jq .
  else
    cat
  fi
}

run_cmd() {
  local desc="$1"
  local outfile="$2"
  shift 2
  log "$desc"
  if "$@" >"$outfile" 2>"${outfile}.err"; then
    rm -f "${outfile}.err"
  else
    printf 'Command failed: %s\n' "$desc" >>"$TMP_DIR/metadata/errors.txt"
    printf '  Output: %s\n' "$outfile" >>"$TMP_DIR/metadata/errors.txt"
    if [[ -s "${outfile}.err" ]]; then
      cat "${outfile}.err" >>"$TMP_DIR/metadata/errors.txt"
    fi
    return 0
  fi
}

run_aws_json() {
  local desc="$1"
  local outfile="$2"
  shift 2
  run_cmd "$desc" "$outfile" aws --no-cli-pager "$@" --output json
}

run_aws_text() {
  local desc="$1"
  local outfile="$2"
  shift 2
  run_cmd "$desc" "$outfile" aws --no-cli-pager "$@" --output text
}

log "Starting collection in $OUT_ROOT"

run_aws_json "Record caller identity" "$TMP_DIR/metadata/sts-get-caller-identity.json" sts get-caller-identity
run_aws_json "List enabled regions from EC2" "$TMP_DIR/metadata/ec2-describe-regions.json" ec2 describe-regions --all-regions
run_aws_json "Describe current AWS Config recorders" "$TMP_DIR/config/describe-configuration-recorders.json" configservice describe-configuration-recorders
run_aws_json "Describe AWS Config recorder status" "$TMP_DIR/config/describe-configuration-recorder-status.json" configservice describe-configuration-recorder-status
run_aws_json "Describe AWS Config aggregators" "$TMP_DIR/config/describe-configuration-aggregators.json" configservice describe-configuration-aggregators

AGG_NAME=""
if have_cmd jq; then
  AGG_NAME="$(jq -r '.ConfigurationAggregators[0].ConfigurationAggregatorName // empty' "$TMP_DIR/config/describe-configuration-aggregators.json" 2>/dev/null || true)"
fi

if [[ -z "$AGG_NAME" ]]; then
  log "No AWS Config aggregator found; aggregate inventory files will be skipped"
else
  printf '%s\n' "$AGG_NAME" > "$TMP_DIR/metadata/config-aggregator-name.txt"
  for rt in "${RESOURCE_TYPES[@]}"; do
    safe_rt="${rt//:/_}"
    safe_rt="${safe_rt//./_}"
    run_aws_json "Aggregate discovered resources for $rt" "$TMP_DIR/config/discovered-${safe_rt}.json" \
      configservice list-aggregate-discovered-resources \
      --configuration-aggregator-name "$AGG_NAME" \
      --resource-type "$rt"
  done

  run_aws_json "Aggregate resource count summary by type" "$TMP_DIR/config/aggregate-resource-summary.json" \
    configservice get-aggregate-discovered-resource-counts \
    --configuration-aggregator-name "$AGG_NAME" \
    --group-by-key RESOURCE_TYPE
  run_aws_json "Aggregate resource count by account" "$TMP_DIR/config/aggregate-resource-counts-by-account.json" \
    configservice get-aggregate-discovered-resource-counts \
    --configuration-aggregator-name "$AGG_NAME" \
    --group-by-key ACCOUNT_ID
  run_aws_json "Aggregate resource count by region" "$TMP_DIR/config/aggregate-resource-counts-by-region.json" \
    configservice get-aggregate-discovered-resource-counts \
    --configuration-aggregator-name "$AGG_NAME" \
    --group-by-key AWS_REGION
fi

run_aws_json "CloudTrail recent management events for current region" "$TMP_DIR/cloudtrail/lookup-events.json" \
  cloudtrail lookup-events --max-results 50

run_aws_json "Security Hub findings" "$TMP_DIR/securityhub/get-findings.json" \
  securityhub get-findings --max-results 100

run_aws_json "Inspector findings" "$TMP_DIR/inspector/list-findings.json" \
  inspector2 list-findings --max-results 100

REGIONS=()
if have_cmd jq; then
  mapfile -t REGIONS < <(jq -r '.Regions[]?.RegionName // empty' "$TMP_DIR/metadata/ec2-describe-regions.json" 2>/dev/null | awk 'NF')
fi
if [[ ${#REGIONS[@]} -eq 0 ]]; then
  REGIONS=("$AWS_REGION_FALLBACK")
fi

for region in "${REGIONS[@]}"; do
  safe_region="${region//./_}"
  run_cmd "Tagging API resources in $region" "$TMP_DIR/tags/get-resources-${safe_region}.json" \
    aws --no-cli-pager --region "$region" resourcegroupstaggingapi get-resources --output json --resources-per-page 100
  run_cmd "CloudTrail management events in $region" "$TMP_DIR/cloudtrail/lookup-events-${safe_region}.json" \
    aws --no-cli-pager --region "$region" cloudtrail lookup-events --max-results 50 --output json
  run_cmd "Security Hub findings in $region" "$TMP_DIR/securityhub/get-findings-${safe_region}.json" \
    aws --no-cli-pager --region "$region" securityhub get-findings --max-results 100 --output json
  run_cmd "Inspector findings in $region" "$TMP_DIR/inspector/list-findings-${safe_region}.json" \
    aws --no-cli-pager --region "$region" inspector2 list-findings --max-results 100 --output json
done

cat > "$TMP_DIR/metadata/README.txt" <<'TXT'
CM-08 AWS evidence bundle

Contents:
- metadata/: caller identity, region list, run log, errors
- config/: AWS Config recorder, aggregator, inventory, and summary outputs
- tags/: Resource Groups Tagging API outputs by region
- cloudtrail/: recent management events by region
- securityhub/: findings by region
- inspector/: Inspector findings by region
TXT

cat > "$TMP_DIR/scripts/run-command.txt" <<TXT
aws sts get-caller-identity
aws configservice describe-configuration-recorders
aws configservice describe-configuration-recorder-status
aws configservice describe-configuration-aggregators
aws configservice get-aggregate-discovered-resource-counts --configuration-aggregator-name ${AGG_NAME:-AGGREGATOR_NAME} --group-by-key RESOURCE_TYPE
aws configservice list-aggregate-discovered-resources --configuration-aggregator-name ${AGG_NAME:-AGGREGATOR_NAME} --resource-type AWS::EC2::Instance
aws cloudtrail lookup-events --max-results 50
aws securityhub get-findings --max-results 100
aws inspector2 list-findings --max-results 100
aws resourcegroupstaggingapi get-resources --resources-per-page 100
TXT

mkdir -p "$OUT_ROOT"
cp -R "$TMP_DIR"/* "$OUT_ROOT"/

if have_cmd tar; then
  tar -czf "${OUT_ROOT}.tar.gz" -C "$(dirname "$OUT_ROOT")" "$(basename "$OUT_ROOT")"
  log "Created archive ${OUT_ROOT}.tar.gz"
fi

log "Done"
printf 'Evidence folder: %s\n' "$OUT_ROOT"
if [[ -f "${OUT_ROOT}.tar.gz" ]]; then
  printf 'Archive: %s\n' "${OUT_ROOT}.tar.gz"
fi
