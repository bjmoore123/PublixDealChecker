"""lambda/helpers.py — Shared utilities, DynamoDB table references, and constants.

Imported by all other lambda modules. Contains no business logic.
"""
import json
import os
import hashlib
import hmac
import secrets
import re
import urllib.parse
import boto3
from decimal import Decimal
from datetime import datetime, timezone, timedelta

# ── AWS clients ───────────────────────────────────────────────────────────────

_region       = os.environ.get("PDC_REGION", "us-east-1")
dynamodb      = boto3.resource("dynamodb")
lambda_client = boto3.client("lambda", region_name=_region)
logs_client   = boto3.client("logs",   region_name=_region)

users_table     = dynamodb.Table(os.environ["USERS_TABLE"])
sessions_table  = dynamodb.Table(os.environ["SESSIONS_TABLE"])
scrape_logs_tbl = dynamodb.Table(os.environ["SCRAPE_LOGS_TABLE"])
auth_logs_tbl   = dynamodb.Table(os.environ["AUTH_LOGS_TABLE"])
app_logs_tbl    = dynamodb.Table(os.environ["APP_LOGS_TABLE"])
history_tbl     = dynamodb.Table(os.environ.get("HISTORY_TABLE",  "publix-deal-checker-deal-history"))
corpus_tbl      = dynamodb.Table(os.environ.get("CORPUS_TABLE",   "publix-deal-checker-deal-corpus"))

# ── Configuration ─────────────────────────────────────────────────────────────

ADMIN_SECRET     = (os.environ.get("ADMIN_SECRET", "") or "").strip()
SCRAPER_FUNCTION = os.environ.get("SCRAPER_FUNCTION", "publix-deal-checker-scraper")
LOG_GROUP        = f"/aws/lambda/{SCRAPER_FUNCTION}"
UNSUB_SECRET     = (os.environ.get("UNSUB_SECRET", "changeme-set-in-deploy") or "").strip()
FRONTEND_URL     = (os.environ.get("FRONTEND_URL", "") or "").strip()
API_URL          = (os.environ.get("API_URL", "") or "").strip()
INBOUND_EMAIL_ADDR    = (os.environ.get("INBOUND_EMAIL_ADDR", "") or "").strip()
RESEND_WEBHOOK_SECRET = (os.environ.get("RESEND_WEBHOOK_SECRET", "") or "").strip()

SESSION_TTL_HOURS     = 72
LOGIN_MAX_ATTEMPTS    = 5
LOGIN_LOCKOUT_MINUTES = 60

CORS = {
    "Access-Control-Allow-Origin":  FRONTEND_URL if FRONTEND_URL else "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Content-Type": "application/json",
}

DEFAULT_PREFS = {
    "store_id":      "",
    "store_name":    "",
    "store_address": "",
    "notify_email":  "",
    "email_enabled": True,
    "items":         [],
    "matching":      {"threshold": 75},
    "notifications": {"only_matches": True},
}

ALLOWED_PREF_KEYS = {
    "store_id", "store_name", "store_address", "notify_email",
    "email_enabled", "items", "matching", "notifications",
}

# ── JSON encoder ──────────────────────────────────────────────────────────────

class _Enc(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return int(o) if o == int(o) else float(o)
        return super().default(o)

# ── Response helpers ──────────────────────────────────────────────────────────

def ok(body, status=200):
    return {"statusCode": status, "headers": CORS, "body": json.dumps(body, cls=_Enc)}

def err(msg, status=400, _extra=None):
    if status >= 400 and status not in (401, 404, 429):
        try:
            from logging_utils import _log_app_event
            _log_app_event("api", "error" if status >= 500 else "warn",
                           status=status, message=str(msg)[:300])
        except Exception as e:
            print(f"[PDC] err logging failed: {e}")
    body = {"error": msg}
    if _extra:
        body.update(_extra)
    return {"statusCode": status, "headers": CORS, "body": json.dumps(body)}

# ── Data helpers ──────────────────────────────────────────────────────────────

def _to_py(obj):
    """Recursively convert DynamoDB Decimal types to int/float."""
    if isinstance(obj, Decimal):
        return int(obj) if obj == int(obj) else float(obj)
    if isinstance(obj, dict):  return {k: _to_py(v) for k, v in obj.items()}
    if isinstance(obj, list):  return [_to_py(i) for i in obj]
    return obj

def get_body(event) -> dict:
    try:    return json.loads(event.get("body") or "{}")
    except Exception: return {}

def itemName(item) -> str:
    """Extract the display name from a list item (dict or plain string)."""
    if isinstance(item, dict): return item.get("name", "")
    return str(item)

# ── IP extraction ─────────────────────────────────────────────────────────────

def _get_client_ip(event: dict) -> str:
    """Extract real client IP from API Gateway event (authoritative sourceIp only).
    X-Forwarded-For is attacker-controllable and not used (PDC-12)."""
    return (event.get("requestContext", {})
                 .get("http", {})
                 .get("sourceIp", "unknown"))

# ── PIN hashing (scrypt) ──────────────────────────────────────────────────────

def hash_pin(pin: str, salt: bytes = None) -> str:
    """Hash a PIN with scrypt + random salt.
    Returns 'scrypt$<hex_salt>$<hex_hash>'."""
    if salt is None:
        salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pin.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${h.hex()}"

def verify_pin(pin: str, stored_hash: str) -> bool:
    """Verify a PIN against a stored scrypt hash.
    Legacy unsalted SHA-256 hashes are rejected (force re-registration)."""
    if not stored_hash or "$" not in stored_hash:
        return False
    try:
        parts = stored_hash.split("$")
        if parts[0] != "scrypt" or len(parts) != 3:
            return False
        salt = bytes.fromhex(parts[1])
        h    = hashlib.scrypt(pin.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(h.hex(), parts[2])
    except Exception:
        return False

# ── Unsubscribe token helpers ─────────────────────────────────────────────────

def _unsub_token(email: str) -> str:
    return hmac.new(
        UNSUB_SECRET.encode(),
        email.lower().strip().encode(),
        hashlib.sha256,
    ).hexdigest()

def _verify_unsub_token(email: str, token: str) -> bool:
    expected = _unsub_token(email)
    return hmac.compare_digest(expected, token.lower().strip())

# ── Session & admin auth ──────────────────────────────────────────────────────

def get_session(event):
    """Validate Bearer token, return session item or None."""
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    token   = headers.get("authorization", "").replace("Bearer ", "").replace("bearer ", "").strip()
    if not token: return None
    item = sessions_table.get_item(Key={"token": token}).get("Item")
    if not item: return None
    now_ts = int(datetime.now(timezone.utc).timestamp())
    if item.get("expires_at", 0) < now_ts: return None
    # PDC-18: reject sessions issued before user's valid_after timestamp (set on logout)
    email = item.get("email", "")
    if email and email != "__admin__":
        try:
            user = users_table.get_item(Key={"email": email}).get("Item")
            if user:
                valid_after      = int(user.get("valid_after", 0))
                session_created  = int(item.get("session_created_at", 0))
                if valid_after and session_created and session_created < valid_after:
                    return None
        except Exception:
            pass  # never let this check break auth
    return item

def get_admin_auth(event) -> bool:
    """Return True if the request carries a valid admin secret.
    Requires 'AdminSecret <secret>' header prefix (PDC-10).
    Uses hmac.compare_digest to prevent timing attacks (PDC-15)."""
    if not ADMIN_SECRET: return False
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    auth    = headers.get("authorization", "").strip()
    for prefix in ("AdminSecret ", "adminsecret "):
        if auth.lower().startswith(prefix.lower()):
            candidate = auth[len(prefix):].strip()
            return hmac.compare_digest(candidate, ADMIN_SECRET)
    return False
