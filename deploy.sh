#!/bin/bash
# =============================================================================
#  deploy.sh — Publix Deal Checker v6 (Fully Serverless)
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

# UNSUB_SECRET: salt for HMAC-based unsubscribe tokens. Auto-generated if not set.
# Rotating this value invalidates all existing unsubscribe links.
if [ -z "${UNSUB_SECRET}" ]; then
  UNSUB_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || cat /dev/urandom | head -c 32 | base64 | tr -d '=+/\n' | head -c 64)
  echo "   ℹ️  No UNSUB_SECRET set — generated automatically."
  echo "   To keep unsubscribe links stable across re-deploys, set UNSUB_SECRET=... before running deploy.sh"
fi

# INBOUND_EMAIL_ADDR: Resend inbound address for list-import emails.
# Change only this variable if the Resend address ever rotates.
INBOUND_EMAIL_ADDR="${INBOUND_EMAIL_ADDR:-cartwise@minaushii.resend.app}"

# RESEND_WEBHOOK_SECRET: Svix signing secret from Resend Webhooks dashboard.
# Must be set manually after registering the webhook. Lambda returns 400 until set.
if [ -z "${RESEND_WEBHOOK_SECRET}" ]; then
  echo "   ⚠️  RESEND_WEBHOOK_SECRET not set — inbound webhook will reject all requests."
  echo "   Obtain it from Resend dashboard after webhook registration, then re-deploy."
  RESEND_WEBHOOK_SECRET="not-yet-configured"
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
echo "║   Publix Deal Checker v6 — Serverless Deployment     ║"
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

create_table "${APP_NAME}-users"        "email"
create_table "${APP_NAME}-sessions"     "token"
create_table "${APP_NAME}-deals"        "store_id"
create_table "${APP_NAME}-scrape-logs"  "job_id"
create_table "${APP_NAME}-auth-logs"    "log_id"
create_table "${APP_NAME}-app-logs"     "log_id"
create_table "${APP_NAME}-deal-history" "store_id"
create_table "${APP_NAME}-deal-corpus"  "corpus_id"

# Enable TTL on deal-history (expires_at attribute)
# Wait for table to reach ACTIVE status before attempting TTL update
if exists aws dynamodb describe-table --table-name "${APP_NAME}-deal-history" --region "${AWS_REGION}"; then
  TTL_STATUS=$(aws dynamodb describe-time-to-live \
    --table-name "${APP_NAME}-deal-history" --region "${AWS_REGION}" \
    --query 'TimeToLiveDescription.TimeToLiveStatus' --output text 2>/dev/null)
  if [ "${TTL_STATUS}" != "ENABLED" ]; then
    info "Waiting for deal-history table to become ACTIVE..."
    aws dynamodb wait table-exists --table-name "${APP_NAME}-deal-history" --region "${AWS_REGION}"
    TABLE_STATUS=""
    for i in $(seq 1 20); do
      TABLE_STATUS=$(aws dynamodb describe-table \
        --table-name "${APP_NAME}-deal-history" --region "${AWS_REGION}" \
        --query 'Table.TableStatus' --output text 2>/dev/null)
      [ "${TABLE_STATUS}" = "ACTIVE" ] && break
      info "  Table status: ${TABLE_STATUS} — waiting 5s..."
      sleep 5
    done
    if [ "${TABLE_STATUS}" = "ACTIVE" ]; then
      aws dynamodb update-time-to-live \
        --table-name "${APP_NAME}-deal-history" \
        --time-to-live-specification "Enabled=true,AttributeName=expires_at" \
        --region "${AWS_REGION}" > /dev/null
      ok "TTL enabled on deal-history (expires_at)"
    else
      echo "   ⚠️  deal-history table did not reach ACTIVE in time — TTL not set. Re-run deploy.sh to retry."
    fi
  else
    skip "TTL on deal-history (already enabled)"
  fi
fi

# Enable TTL on remaining tables (sessions, deals, auth-logs, app-logs)
# All use expires_at attribute; idempotent — safe to re-run
enable_ttl() {
  local tbl="${APP_NAME}-$1"
  if exists aws dynamodb describe-table --table-name "${tbl}" --region "${AWS_REGION}"; then
    local status
    status=$(aws dynamodb describe-time-to-live \
      --table-name "${tbl}" --region "${AWS_REGION}" \
      --query 'TimeToLiveDescription.TimeToLiveStatus' --output text 2>/dev/null)
    if [ "${status}" != "ENABLED" ]; then
      aws dynamodb update-time-to-live \
        --table-name "${tbl}" \
        --time-to-live-specification "Enabled=true,AttributeName=expires_at" \
        --region "${AWS_REGION}" > /dev/null 2>&1 \
        && ok "TTL enabled on ${tbl} (expires_at)" \
        || echo "   ⚠️  TTL on ${tbl} not set (table may still be creating — re-run to retry)"
    else
      skip "TTL on ${tbl} (already enabled)"
    fi
  fi
}

enable_ttl "sessions"
enable_ttl "deals"
enable_ttl "auth-logs"
enable_ttl "app-logs"
enable_ttl "scrape-logs"

# ── STEP 2: IAM role ──────────────────────────────────────────────────────────
echo "▶  2/8  IAM role"

LAMBDA_ROLE="${APP_NAME}-lambda-role"
if ! exists aws iam get-role --role-name "${LAMBDA_ROLE}"; then
  aws iam create-role --role-name "${LAMBDA_ROLE}" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' > /dev/null
  aws iam attach-role-policy --role-name "${LAMBDA_ROLE}" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
  ok "IAM role: ${LAMBDA_ROLE}"
  info "Waiting 10s for role to propagate..."
  sleep 10
fi

# Always refresh inline policy to ensure new table permissions are present
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
       \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-app-logs\",
       \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-deal-history\",
       \"arn:aws:dynamodb:${AWS_REGION}:${AWS_ACCOUNT_ID}:table/${APP_NAME}-deal-corpus\"
     ]},
    {\"Effect\":\"Allow\",\"Action\":[\"lambda:InvokeFunction\"],
     \"Resource\":\"arn:aws:lambda:${AWS_REGION}:${AWS_ACCOUNT_ID}:function:${APP_NAME}-scraper\"},
    {\"Effect\":\"Allow\",\"Action\":[\"logs:DescribeLogStreams\",\"logs:GetLogEvents\",\"logs:FilterLogEvents\"],
     \"Resource\":\"arn:aws:logs:${AWS_REGION}:${AWS_ACCOUNT_ID}:log-group:/aws/lambda/${APP_NAME}-scraper:*\"}
  ]}" > /dev/null
skip "IAM role: ${LAMBDA_ROLE} (policy refreshed)"

LAMBDA_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${LAMBDA_ROLE}"

# ── STEP 3: API Lambda ────────────────────────────────────────────────────────
echo "▶  3/8  API Lambda"

LAMBDA_API="${APP_NAME}-api"
LAMBDA_API_ZIP="${TMPDIR_PY}/lambda_api.zip"

if [ ! -f "${SCRIPT_DIR}/lambda/handler.py" ]; then echo "ERROR: lambda/handler.py not found"; exit 1; fi

PIP_CMD=$(which pip3 2>/dev/null || which pip 2>/dev/null || echo "python3 -m pip")

API_BUILD_TMP="${TMPDIR_PY}/api_build"
rm -rf "${API_BUILD_TMP}"; mkdir -p "${API_BUILD_TMP}"
# Copy all lambda modules (Architecture #1: modular split)
for f in handler.py helpers.py auth.py prefs.py deals.py admin.py inbound.py logging_utils.py; do
  cp "${SCRIPT_DIR}/lambda/${f}" "${API_BUILD_TMP}/"
done
# Include shared deal_parser (Architecture #2: shared library)
mkdir -p "${API_BUILD_TMP}/shared"
cp "${SCRIPT_DIR}/shared/__init__.py"   "${API_BUILD_TMP}/shared/"
cp "${SCRIPT_DIR}/shared/deal_parser.py" "${API_BUILD_TMP}/shared/"
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

API_ENV="Variables={USERS_TABLE=${APP_NAME}-users,SESSIONS_TABLE=${APP_NAME}-sessions,DEALS_TABLE=${APP_NAME}-deals,SCRAPE_LOGS_TABLE=${APP_NAME}-scrape-logs,AUTH_LOGS_TABLE=${APP_NAME}-auth-logs,APP_LOGS_TABLE=${APP_NAME}-app-logs,HISTORY_TABLE=${APP_NAME}-deal-history,CORPUS_TABLE=${APP_NAME}-deal-corpus,ADMIN_SECRET=${ADMIN_SECRET},SCRAPER_FUNCTION=${APP_NAME}-scraper,PDC_REGION=${AWS_REGION},RESEND_API_KEY=${RESEND_API_KEY},RESEND_FROM_NAME=${RESEND_FROM_NAME},RESEND_FROM_ADDR=${RESEND_FROM_ADDR},FRONTEND_URL=${FRONTEND_URL},API_URL=${API_URL},UNSUB_SECRET=${UNSUB_SECRET},INBOUND_EMAIL_ADDR=${INBOUND_EMAIL_ADDR},RESEND_WEBHOOK_SECRET=${RESEND_WEBHOOK_SECRET}}"

if ! exists aws lambda get-function --function-name "${LAMBDA_API}" --region "${AWS_REGION}"; then
  aws lambda create-function \
    --function-name "${LAMBDA_API}" \
    --runtime python3.12 \
    --role "${LAMBDA_ROLE_ARN}" \
    --handler handler.handler \
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
    --handler handler.handler \
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
# Include shared deal_parser (Architecture #2: shared library)
mkdir -p "${SCRAPER_TMP}/shared"
cp "${SCRIPT_DIR}/shared/__init__.py"    "${SCRAPER_TMP}/shared/"
cp "${SCRIPT_DIR}/shared/deal_parser.py" "${SCRAPER_TMP}/shared/"

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

SCRAPER_ENV="Variables={FRONTEND_URL=${FRONTEND_URL},API_URL=${API_URL},UNSUB_SECRET=${UNSUB_SECRET},USERS_TABLE=${APP_NAME}-users,DEALS_TABLE=${APP_NAME}-deals,SCRAPE_LOGS_TABLE=${APP_NAME}-scrape-logs,APP_LOGS_TABLE=${APP_NAME}-app-logs,HISTORY_TABLE=${APP_NAME}-deal-history,CORPUS_TABLE=${APP_NAME}-deal-corpus,RESEND_API_KEY=${RESEND_KEY_VAL},RESEND_FROM_NAME=${RESEND_FROM_NAME},RESEND_FROM_ADDR=${RESEND_FROM_ADDR},PDC_REGION=${AWS_REGION}}"

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
js = open(r'${SCRIPT_DIR_PY}/frontend/app.js', encoding='utf-8').read()
js_out = js.replace('https://YOUR_API_GATEWAY_URL', '${API_URL}')
open('app_deploy_tmp.js', 'w', encoding='utf-8').write(js_out)
"
MSYS_NO_PATHCONV=1 aws s3 cp index_deploy_tmp.html \
  "s3://${S3_FRONTEND}/index.html" \
  --content-type "text/html" --cache-control "no-cache, no-store, must-revalidate" --no-progress
MSYS_NO_PATHCONV=1 aws s3 cp app_deploy_tmp.js \
  "s3://${S3_FRONTEND}/app.js" \
  --content-type "application/javascript" --cache-control "no-cache, no-store, must-revalidate" --no-progress
rm -f index_deploy_tmp.html app_deploy_tmp.js
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

# ── Final env update: re-apply both Lambda configs now that API_URL and FRONTEND_URL are known ──
# On first deploy these were empty; this pass fills them in correctly.
API_ENV="Variables={USERS_TABLE=${APP_NAME}-users,SESSIONS_TABLE=${APP_NAME}-sessions,DEALS_TABLE=${APP_NAME}-deals,SCRAPE_LOGS_TABLE=${APP_NAME}-scrape-logs,AUTH_LOGS_TABLE=${APP_NAME}-auth-logs,APP_LOGS_TABLE=${APP_NAME}-app-logs,HISTORY_TABLE=${APP_NAME}-deal-history,CORPUS_TABLE=${APP_NAME}-deal-corpus,ADMIN_SECRET=${ADMIN_SECRET},SCRAPER_FUNCTION=${APP_NAME}-scraper,PDC_REGION=${AWS_REGION},RESEND_API_KEY=${RESEND_API_KEY},RESEND_FROM_NAME=${RESEND_FROM_NAME},RESEND_FROM_ADDR=${RESEND_FROM_ADDR},FRONTEND_URL=${FRONTEND_URL},API_URL=${API_URL},UNSUB_SECRET=${UNSUB_SECRET},INBOUND_EMAIL_ADDR=${INBOUND_EMAIL_ADDR},RESEND_WEBHOOK_SECRET=${RESEND_WEBHOOK_SECRET}}"
SCRAPER_ENV="Variables={FRONTEND_URL=${FRONTEND_URL},API_URL=${API_URL},UNSUB_SECRET=${UNSUB_SECRET},USERS_TABLE=${APP_NAME}-users,DEALS_TABLE=${APP_NAME}-deals,SCRAPE_LOGS_TABLE=${APP_NAME}-scrape-logs,APP_LOGS_TABLE=${APP_NAME}-app-logs,HISTORY_TABLE=${APP_NAME}-deal-history,CORPUS_TABLE=${APP_NAME}-deal-corpus,RESEND_API_KEY=${RESEND_KEY_VAL},RESEND_FROM_NAME=${RESEND_FROM_NAME},RESEND_FROM_ADDR=${RESEND_FROM_ADDR},PDC_REGION=${AWS_REGION}}"
aws lambda update-function-configuration --function-name "${LAMBDA_API}"     --environment "${API_ENV}"     --region "${AWS_REGION}" > /dev/null
aws lambda wait function-updated         --function-name "${LAMBDA_API}"     --region "${AWS_REGION}"       2>/dev/null || sleep 5
aws lambda update-function-configuration --function-name "${LAMBDA_SCRAPER}" --environment "${SCRAPER_ENV}" --region "${AWS_REGION}" > /dev/null
ok "Lambda env vars updated with final URLs (FRONTEND_URL, API_URL, UNSUB_SECRET)"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║  ✅  Deployment complete!  (v6)                                   ║"
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
