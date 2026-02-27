#!/bin/bash
# =============================================================================
#  deploy.sh — Publix Deal Checker v4 (Fully Serverless)
#  Idempotent: safe to re-run. Everything existing is skipped or updated.
#  Usage: RESEND_API_KEY="re_xxx" ADMIN_SECRET="yourpassword" bash deploy.sh
# =============================================================================

export MSYS_NO_PATHCONV=1
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_DIR_PY="$(cygpath -w "${SCRIPT_DIR}" 2>/dev/null || echo "${SCRIPT_DIR}")"
TMPDIR_PY="$(cygpath -w "$(mktemp -d)" 2>/dev/null || mktemp -d)"
win_path() { cygpath -w "$1" 2>/dev/null || echo "$1"; }

AWS_REGION="us-east-1"
APP_NAME="publix-deal-checker"
RESEND_FROM_NAME="Publix Alerts"
RESEND_FROM_ADDR="onboarding@resend.dev"

if [ -z "${RESEND_API_KEY}" ]; then
  echo "ERROR: RESEND_API_KEY is not set."
  echo "Usage: RESEND_API_KEY=\"re_xxx\" ADMIN_SECRET=\"yourpassword\" bash deploy.sh"
  exit 1
fi

if [ -z "${ADMIN_SECRET}" ]; then
  ADMIN_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))" 2>/dev/null || cat /dev/urandom | head -c 24 | base64 | tr -d '=+/')
  echo "   ℹ️  No ADMIN_SECRET set — generated: ${ADMIN_SECRET}"
  echo "   Save this — you'll need it to access the Admin panel."
fi

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
S3_FRONTEND="${APP_NAME}-frontend-${AWS_ACCOUNT_ID}"
FRONTEND_URL="http://${S3_FRONTEND}.s3-website-${AWS_REGION}.amazonaws.com"

ok()     { echo "   ✓ $*"; }
skip()   { echo "   - $* (already exists)"; }
info()   { echo "   → $*"; }
exists() { "$@" > /dev/null 2>&1; }

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Publix Deal Checker v5 — Serverless Deployment     ║"
echo "║   Account: ${AWS_ACCOUNT_ID}   Region: ${AWS_REGION} ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── STEP 1: DynamoDB tables ───────────────────────────────────────────────────
echo "▶  1/8  DynamoDB tables"

create_table() {
  local name="$1" pk="$2" pktype="${3:-S}"
  if ! exists aws dynamodb describe-table --table-name "${name}" --region "${AWS_REGION}"; then
    aws dynamodb create-table --table-name "${name}" \
      --attribute-definitions AttributeName="${pk}",AttributeType="${pktype}" \
      --key-schema AttributeName="${pk}",KeyType=HASH \
      --billing-mode PAY_PER_REQUEST --region "${AWS_REGION}" > /dev/null
    ok "DynamoDB table: ${name}"
  else
    skip "DynamoDB table: ${name}"
  fi
}

create_table "${APP_NAME}-users"       "email"
create_table "${APP_NAME}-sessions"    "token"
create_table "${APP_NAME}-deals"       "store_id"
create_table "${APP_NAME}-scrape-logs" "job_id"
create_table "${APP_NAME}-auth-logs"   "log_id"
create_table "${APP_NAME}-app-logs"    "log_id"

# ── STEP 2: IAM role ──────────────────────────────────────────────────────────
echo "▶  2/8  IAM role"

LAMBDA_ROLE="${APP_NAME}-lambda-role"
if ! exists aws iam get-role --role-name "${LAMBDA_ROLE}"; then
  aws iam create-role --role-name "${LAMBDA_ROLE}" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' > /dev/null
  aws iam attach-role-policy --role-name "${LAMBDA_ROLE}" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
  aws iam put-role-policy --role-name "${LAMBDA_ROLE}" \
    --policy-name "${APP_NAME}-lambda-policy" \
    --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[
      {\"Effect\":\"Allow\",\"Action\":[\"dynamodb:GetItem\",\"dynamodb:PutItem\",\"dynamodb:UpdateItem\",\"dynamodb:DeleteItem\",\"dynamodb:Scan\",\"dynamodb:Query\"],
       \"Resource\":[
         \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-users\",
         \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-sessions\",
         \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-deals\",
         \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-scrape-logs\",
               \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-auth-logs\",
               \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-app-logs\"
       ]},
      {\"Effect\":\"Allow\",\"Action\":[\"lambda:InvokeFunction\"],
       \"Resource\":\"arn:aws:lambda:${AWS_REGION}:${AWS_ACCOUNT_ID}:function:${APP_NAME}-scraper\"},
      {\"Effect\":\"Allow\",\"Action\":[\"logs:DescribeLogStreams\",\"logs:GetLogEvents\",\"logs:FilterLogEvents\"],
       \"Resource\":\"arn:aws:logs:${AWS_REGION}:${AWS_ACCOUNT_ID}:log-group:/aws/lambda/${APP_NAME}-scraper:*\"}
    ]}"
  ok "IAM role: ${LAMBDA_ROLE}"
  info "Waiting 10s for role to propagate..."
  sleep 10
else
  # Update inline policy to ensure new permissions exist
  aws iam put-role-policy --role-name "${LAMBDA_ROLE}" \
    --policy-name "${APP_NAME}-lambda-policy" \
    --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[
      {\"Effect\":\"Allow\",\"Action\":[\"dynamodb:GetItem\",\"dynamodb:PutItem\",\"dynamodb:UpdateItem\",\"dynamodb:DeleteItem\",\"dynamodb:Scan\",\"dynamodb:Query\"],
       \"Resource\":[
         \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-users\",
         \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-sessions\",
         \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-deals\",
         \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-scrape-logs\",
               \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-auth-logs\",
               \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-app-logs\"
       ]},
      {\"Effect\":\"Allow\",\"Action\":[\"lambda:InvokeFunction\"],
       \"Resource\":\"arn:aws:lambda:${AWS_REGION}:${AWS_ACCOUNT_ID}:function:${APP_NAME}-scraper\"},
      {\"Effect\":\"Allow\",\"Action\":[\"logs:DescribeLogStreams\",\"logs:GetLogEvents\",\"logs:FilterLogEvents\"],
       \"Resource\":\"arn:aws:logs:${AWS_REGION}:${AWS_ACCOUNT_ID}:log-group:/aws/lambda/${APP_NAME}-scraper:*\"}
    ]}" > /dev/null
  skip "IAM role: ${LAMBDA_ROLE} (policy refreshed)"
fi

LAMBDA_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${LAMBDA_ROLE}"

# ── STEP 3: API Lambda ────────────────────────────────────────────────────────
echo "▶  3/8  API Lambda"

LAMBDA_API="${APP_NAME}-api"
LAMBDA_API_ZIP="${TMPDIR_PY}/lambda_api.zip"

if [ ! -f "${SCRIPT_DIR}/lambda/api.py" ]; then echo "ERROR: lambda/api.py not found"; exit 1; fi

PIP_CMD=$(which pip3 2>/dev/null || which pip 2>/dev/null || echo "python3 -m pip")

API_BUILD_TMP="${TMPDIR_PY}/api_build"
rm -rf "${API_BUILD_TMP}"; mkdir -p "${API_BUILD_TMP}"
cp "${SCRIPT_DIR}/lambda/api.py" "${API_BUILD_TMP}/"
info "Installing api dependencies (resend)..."
${PIP_CMD} install resend \
  --target "${API_BUILD_TMP}" --quiet \
  --platform manylinux2014_x86_64 \
  --python-version 3.12 \
  --only-binary=:all: 2>/dev/null || \
${PIP_CMD} install resend --target "${API_BUILD_TMP}" --quiet
python3 -c "
import zipfile, os
build_dir=r'${API_BUILD_TMP}'
dst=r'${LAMBDA_API_ZIP}'
with zipfile.ZipFile(dst,'w',zipfile.ZIP_DEFLATED) as z:
    for root,dirs,files in os.walk(build_dir):
        dirs[:]=[d for d in dirs if d not in ['__pycache__']]
        for f in files:
            if f.endswith('.pyc'): continue
            fp=os.path.join(root,f)
            z.write(fp,os.path.relpath(fp,build_dir))
print('API zip: '+dst)
" || { echo "ERROR: Failed to create API zip"; exit 1; }

API_ENV="Variables={USERS_TABLE=${APP_NAME}-users,SESSIONS_TABLE=${APP_NAME}-sessions,DEALS_TABLE=${APP_NAME}-deals,SCRAPE_LOGS_TABLE=${APP_NAME}-scrape-logs,AUTH_LOGS_TABLE=${APP_NAME}-auth-logs,APP_LOGS_TABLE=${APP_NAME}-app-logs,ADMIN_SECRET=${ADMIN_SECRET},SCRAPER_FUNCTION=${APP_NAME}-scraper,PDC_REGION=${AWS_REGION},RESEND_API_KEY=${RESEND_API_KEY},RESEND_FROM_NAME=${RESEND_FROM_NAME},RESEND_FROM_ADDR=${RESEND_FROM_ADDR}}"

if ! exists aws lambda get-function --function-name "${LAMBDA_API}" --region "${AWS_REGION}"; then
  aws lambda create-function \
    --function-name "${LAMBDA_API}" \
    --runtime python3.12 \
    --role "${LAMBDA_ROLE_ARN}" \
    --handler api.handler \
    --zip-file "fileb://$(win_path "${LAMBDA_API_ZIP}")" \
    --timeout 30 \
    --memory-size 256 \
    --environment "${API_ENV}" \
    --region "${AWS_REGION}" > /dev/null
  ok "Lambda created: ${LAMBDA_API}"
else
  aws lambda update-function-code \
    --function-name "${LAMBDA_API}" \
    --zip-file "fileb://$(win_path "${LAMBDA_API_ZIP}")" \
    --region "${AWS_REGION}" > /dev/null
  aws lambda wait function-updated --function-name "${LAMBDA_API}" --region "${AWS_REGION}" 2>/dev/null || sleep 5
  aws lambda update-function-configuration \
    --function-name "${LAMBDA_API}" \
    --environment "${API_ENV}" \
    --region "${AWS_REGION}" > /dev/null
  ok "Lambda updated: ${LAMBDA_API}"
fi

LAMBDA_API_ARN=$(aws lambda get-function --function-name "${LAMBDA_API}" --region "${AWS_REGION}" --query 'Configuration.FunctionArn' --output text)

# ── STEP 4: Scraper Lambda ────────────────────────────────────────────────────
echo "▶  4/8  Scraper Lambda"

LAMBDA_SCRAPER="${APP_NAME}-scraper"
LAMBDA_SCRAPER_ZIP="${TMPDIR_PY}/lambda_scraper.zip"

for f in main.py scraper.py matcher.py; do
  [ ! -f "${SCRIPT_DIR}/scraper/${f}" ] && { echo "ERROR: Missing: ${SCRIPT_DIR}/scraper/${f}"; exit 1; }
done

SCRAPER_TMP="${TMPDIR_PY}/scraper_build"
rm -rf "${SCRAPER_TMP}"; mkdir -p "${SCRAPER_TMP}"
cp "${SCRIPT_DIR}/scraper/main.py"    "${SCRAPER_TMP}/"
cp "${SCRIPT_DIR}/scraper/scraper.py" "${SCRAPER_TMP}/"
cp "${SCRIPT_DIR}/scraper/matcher.py" "${SCRAPER_TMP}/"

info "Installing scraper dependencies..."
${PIP_CMD} install resend rapidfuzz \
  --target "${SCRAPER_TMP}" --quiet \
  --platform manylinux2014_x86_64 \
  --python-version 3.12 \
  --only-binary=:all: 2>/dev/null || \
${PIP_CMD} install resend rapidfuzz --target "${SCRAPER_TMP}" --quiet

python3 -c "
import zipfile, os
build_dir=r'${SCRAPER_TMP}'
dst=r'${LAMBDA_SCRAPER_ZIP}'
with zipfile.ZipFile(dst,'w',zipfile.ZIP_DEFLATED) as z:
    for root,dirs,files in os.walk(build_dir):
        dirs[:]=[d for d in dirs if d not in ['__pycache__']]
        for f in files:
            if f.endswith('.pyc'): continue
            fp=os.path.join(root,f)
            z.write(fp,os.path.relpath(fp,build_dir))
print('Scraper zip: '+dst)
" || { echo "ERROR: Failed to create scraper zip"; exit 1; }

RESEND_KEY_VAL=$(aws ssm get-parameter --name "/publix/resend-api-key" \
  --with-decryption --query Parameter.Value --output text --region "${AWS_REGION}" 2>/dev/null || echo "${RESEND_API_KEY}")

SCRAPER_ENV="Variables={FRONTEND_URL=${FRONTEND_URL},USERS_TABLE=${APP_NAME}-users,DEALS_TABLE=${APP_NAME}-deals,SCRAPE_LOGS_TABLE=${APP_NAME}-scrape-logs,RESEND_API_KEY=${RESEND_KEY_VAL},RESEND_FROM_NAME=${RESEND_FROM_NAME},RESEND_FROM_ADDR=${RESEND_FROM_ADDR},PDC_REGION=${AWS_REGION}}"

if ! exists aws lambda get-function --function-name "${LAMBDA_SCRAPER}" --region "${AWS_REGION}"; then
  aws lambda create-function \
    --function-name "${LAMBDA_SCRAPER}" \
    --runtime python3.12 \
    --role "${LAMBDA_ROLE_ARN}" \
    --handler main.handler \
    --zip-file "fileb://$(win_path "${LAMBDA_SCRAPER_ZIP}")" \
    --timeout 300 \
    --memory-size 512 \
    --environment "${SCRAPER_ENV}" \
    --region "${AWS_REGION}" > /dev/null
  ok "Lambda created: ${LAMBDA_SCRAPER}"
else
  aws lambda update-function-code \
    --function-name "${LAMBDA_SCRAPER}" \
    --zip-file "fileb://$(win_path "${LAMBDA_SCRAPER_ZIP}")" \
    --region "${AWS_REGION}" > /dev/null
  aws lambda wait function-updated --function-name "${LAMBDA_SCRAPER}" --region "${AWS_REGION}" 2>/dev/null || sleep 5
  aws lambda update-function-configuration \
    --function-name "${LAMBDA_SCRAPER}" \
    --environment "${SCRAPER_ENV}" \
    --region "${AWS_REGION}" > /dev/null
  ok "Lambda updated: ${LAMBDA_SCRAPER}"
fi

LAMBDA_SCRAPER_ARN=$(aws lambda get-function --function-name "${LAMBDA_SCRAPER}" --region "${AWS_REGION}" --query 'Configuration.FunctionArn' --output text)

# ── STEP 5: SSM secrets (optional, for reference) ─────────────────────────────
echo "▶  5/8  SSM secrets"
put_ssm() {
  local name="$1" val="$2" type="${3:-SecureString}"
  if ! exists aws ssm get-parameter --name "/publix/${name}" --region "${AWS_REGION}"; then
    aws ssm put-parameter --name "/publix/${name}" --value "${val}" --type "${type}" --region "${AWS_REGION}" > /dev/null
    ok "SSM /publix/${name}"
  else
    skip "SSM /publix/${name}"
  fi
}
put_ssm "resend-api-key"   "${RESEND_API_KEY}"
put_ssm "resend-from-name" "${RESEND_FROM_NAME}" "String"
put_ssm "resend-from-addr" "${RESEND_FROM_ADDR}" "String"

# ── STEP 6: API Gateway ───────────────────────────────────────────────────────
echo "▶  6/8  API Gateway"

API_ID=$(aws apigatewayv2 get-apis --region "${AWS_REGION}" \
  --query "Items[?Name=='${APP_NAME}-api-gw'].ApiId" --output text 2>/dev/null)

if [ -z "${API_ID}" ] || [ "${API_ID}" = "None" ]; then
  API_ID=$(aws apigatewayv2 create-api \
    --name "${APP_NAME}-api-gw" \
    --protocol-type HTTP \
    --cors-configuration AllowOrigins=*,AllowMethods=*,AllowHeaders=* \
    --region "${AWS_REGION}" \
    --query 'ApiId' --output text)
  ok "API Gateway created: ${API_ID}"
else
  aws apigatewayv2 update-api \
    --api-id "${API_ID}" \
    --cors-configuration AllowOrigins=*,AllowMethods=*,AllowHeaders=* \
    --region "${AWS_REGION}" > /dev/null 2>&1 || true
  skip "API Gateway: ${API_ID}"
fi

API_URL="https://${API_ID}.execute-api.${AWS_REGION}.amazonaws.com"

INTEG_ID=$(aws apigatewayv2 get-integrations \
  --api-id "${API_ID}" --region "${AWS_REGION}" \
  --query 'Items[0].IntegrationId' --output text 2>/dev/null)

if [ -z "${INTEG_ID}" ] || [ "${INTEG_ID}" = "None" ]; then
  INTEG_ID=$(aws apigatewayv2 create-integration \
    --api-id "${API_ID}" \
    --integration-type AWS_PROXY \
    --integration-uri "${LAMBDA_API_ARN}" \
    --payload-format-version 2.0 \
    --region "${AWS_REGION}" \
    --query 'IntegrationId' --output text)
  aws apigatewayv2 create-route \
    --api-id "${API_ID}" \
    --route-key "\$default" \
    --target "integrations/${INTEG_ID}" \
    --region "${AWS_REGION}" > /dev/null
  aws apigatewayv2 create-stage \
    --api-id "${API_ID}" \
    --stage-name "\$default" \
    --auto-deploy \
    --region "${AWS_REGION}" > /dev/null
  aws lambda add-permission \
    --function-name "${LAMBDA_API}" \
    --statement-id "apigateway-invoke" \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:${AWS_REGION}:${AWS_ACCOUNT_ID}:${API_ID}/*" \
    --region "${AWS_REGION}" > /dev/null 2>&1 || true
  ok "API Gateway integration + route created"
else
  skip "API Gateway integration"
fi

# ── STEP 7: Frontend ──────────────────────────────────────────────────────────
echo "▶  7/8  Frontend (S3 static site)"

if ! exists aws s3api head-bucket --bucket "${S3_FRONTEND}"; then
  aws s3api create-bucket --bucket "${S3_FRONTEND}" --region "${AWS_REGION}" > /dev/null
  aws s3api put-public-access-block --bucket "${S3_FRONTEND}" \
    --public-access-block-configuration \
    "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
  aws s3api put-bucket-website --bucket "${S3_FRONTEND}" \
    --website-configuration '{"IndexDocument":{"Suffix":"index.html"}}'
  aws s3api put-bucket-policy --bucket "${S3_FRONTEND}" \
    --policy "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::${S3_FRONTEND}/*\"}]}"
  ok "S3 bucket (frontend): ${S3_FRONTEND}"
else
  skip "S3 bucket (frontend): ${S3_FRONTEND}"
fi

python3 -c "
import re, os
src = open(r'${SCRIPT_DIR_PY}/frontend/index.html', encoding='utf-8').read()
out = src.replace('https://YOUR_API_GATEWAY_URL', '${API_URL}')
open('index_deploy_tmp.html', 'w', encoding='utf-8').write(out)
"
MSYS_NO_PATHCONV=1 aws s3 cp index_deploy_tmp.html \
  "s3://${S3_FRONTEND}/index.html" \
  --content-type "text/html" --cache-control "no-cache, no-store, must-revalidate" --no-progress
rm -f index_deploy_tmp.html
FRONTEND_URL="http://${S3_FRONTEND}.s3-website-${AWS_REGION}.amazonaws.com"
ok "Frontend deployed: ${FRONTEND_URL}"

# ── STEP 8: EventBridge ───────────────────────────────────────────────────────
echo "▶  8/8  EventBridge weekly trigger"

RULE_NAME="${APP_NAME}-weekly"
RULE_ARN=$(aws events put-rule \
  --name "${RULE_NAME}" \
  --schedule-expression "cron(0 12 ? * WED *)" \
  --state ENABLED \
  --description "Publix Deal Checker — weekly scraper" \
  --region "${AWS_REGION}" \
  --query 'RuleArn' --output text)
ok "EventBridge rule: ${RULE_NAME}"

aws lambda add-permission \
  --function-name "${LAMBDA_SCRAPER}" \
  --statement-id "eventbridge-invoke" \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn "${RULE_ARN}" \
  --region "${AWS_REGION}" > /dev/null 2>&1 || true

aws events put-targets \
  --rule "${RULE_NAME}" \
  --targets "Id=scraper,Arn=${LAMBDA_SCRAPER_ARN}" \
  --region "${AWS_REGION}" > /dev/null
ok "EventBridge → scraper target set"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║  ✅  Deployment complete!  (v5)                                   ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║  Frontend:  ${FRONTEND_URL}"
echo "║  API:       ${API_URL}"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║  Admin secret (keep this safe!):                                  ║"
echo "║  ${ADMIN_SECRET}"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║  Test scraper now:                                                ║"
echo "║    aws lambda invoke --function-name ${LAMBDA_SCRAPER} \\"
echo "║      --region ${AWS_REGION} /tmp/out.json && cat /tmp/out.json"
echo "║  Tail logs:                                                       ║"
echo "║    aws logs tail /aws/lambda/${LAMBDA_SCRAPER} --follow"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
