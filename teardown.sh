#!/bin/bash
# =============================================================================
#  teardown.sh — Publix Deal Checker v4
#  Removes all AWS resources.
#
#  By default, DynamoDB tables (and all user data) are PRESERVED.
#  Pass --delete-data to also drop all four DynamoDB tables.
#
#  Usage:
#    bash teardown.sh                  # keeps DynamoDB data
#    bash teardown.sh --delete-data    # deletes DynamoDB data too
# =============================================================================
export MSYS_NO_PATHCONV=1
AWS_REGION="us-east-1"
APP_NAME="publix-deal-checker"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
S3_FRONTEND="${APP_NAME}-frontend-${AWS_ACCOUNT_ID}"

DELETE_DATA=false
for arg in "$@"; do
  [ "$arg" = "--delete-data" ] && DELETE_DATA=true
done

ok()   { echo "   ✓ Deleted: $*"; }
skip() { echo "   - Not found: $*"; }
keep() { echo "   ✦ Preserved: $*"; }

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Publix Deal Checker v4 — Teardown                  ║"
if [ "$DELETE_DATA" = "true" ]; then
echo "║   ⚠️  --delete-data: DynamoDB tables WILL be deleted  ║"
else
echo "║   DynamoDB data will be PRESERVED (use --delete-data) ║"
fi
echo "╚══════════════════════════════════════════════════════╝"
echo ""
if [ "$DELETE_DATA" = "true" ]; then
  read -p "Delete ALL resources INCLUDING all user/deal data? (yes/no): " C
else
  read -p "Delete all AWS resources except DynamoDB data? (yes/no): " C
fi
[ "${C}" != "yes" ] && echo "Aborted." && exit 0

echo "▶  EventBridge"
RULE="${APP_NAME}-weekly"
aws events remove-targets --rule "${RULE}" --ids scraper --region "${AWS_REGION}" > /dev/null 2>&1 && ok "EventBridge targets" || skip "EventBridge targets"
aws events delete-rule    --name "${RULE}" --region "${AWS_REGION}" > /dev/null 2>&1 && ok "EventBridge rule" || skip "EventBridge rule"

echo "▶  API Gateway"
API_ID=$(aws apigatewayv2 get-apis --region "${AWS_REGION}" --query "Items[?Name=='${APP_NAME}-api-gw'].ApiId" --output text 2>/dev/null)
[ -n "${API_ID}" ] && [ "${API_ID}" != "None" ] && aws apigatewayv2 delete-api --api-id "${API_ID}" --region "${AWS_REGION}" > /dev/null && ok "API Gateway: ${API_ID}" || skip "API Gateway"

echo "▶  Lambda functions"
for fn in "${APP_NAME}-api" "${APP_NAME}-scraper"; do
  aws lambda delete-function --function-name "${fn}" --region "${AWS_REGION}" > /dev/null 2>&1 && ok "Lambda: ${fn}" || skip "Lambda: ${fn}"
done

echo "▶  IAM role"
ROLE="${APP_NAME}-lambda-role"
aws iam detach-role-policy --role-name "${ROLE}" --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole > /dev/null 2>&1 || true
aws iam delete-role-policy --role-name "${ROLE}" --policy-name "${APP_NAME}-lambda-policy" > /dev/null 2>&1 || true
aws iam delete-role        --role-name "${ROLE}" > /dev/null 2>&1 && ok "IAM role" || skip "IAM role"

echo "▶  DynamoDB tables"
if [ "$DELETE_DATA" = "true" ]; then
  for tbl in "${APP_NAME}-users" "${APP_NAME}-sessions" "${APP_NAME}-deals" "${APP_NAME}-scrape-logs"; do
    aws dynamodb delete-table --table-name "${tbl}" --region "${AWS_REGION}" > /dev/null 2>&1 && ok "DynamoDB: ${tbl}" || skip "DynamoDB: ${tbl}"
  done
else
  for tbl in "${APP_NAME}-users" "${APP_NAME}-sessions" "${APP_NAME}-deals" "${APP_NAME}-scrape-logs"; do
    keep "DynamoDB: ${tbl}"
  done
  echo "   → Re-run with --delete-data to remove all DynamoDB tables and user data."
fi

echo "▶  SSM parameters"
for p in resend-api-key resend-from-name resend-from-addr; do
  aws ssm delete-parameter --name "/publix/${p}" --region "${AWS_REGION}" > /dev/null 2>&1 && ok "SSM: /publix/${p}" || skip "SSM: /publix/${p}"
done

echo "▶  S3 frontend"
if aws s3api head-bucket --bucket "${S3_FRONTEND}" > /dev/null 2>&1; then
  aws s3 rm "s3://${S3_FRONTEND}" --recursive > /dev/null
  aws s3api delete-bucket --bucket "${S3_FRONTEND}" --region "${AWS_REGION}" > /dev/null
  ok "S3: ${S3_FRONTEND}"
else
  skip "S3: ${S3_FRONTEND}"
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
if [ "$DELETE_DATA" = "true" ]; then
echo "║  ✅  Teardown complete (all data deleted).            ║"
else
echo "║  ✅  Teardown complete (DynamoDB data preserved).     ║"
fi
echo "╚══════════════════════════════════════════════════════╝"
echo ""
