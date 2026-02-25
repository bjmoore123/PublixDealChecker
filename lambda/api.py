"""
lambda/api.py  (v4)

API Gateway Lambda handler for Publix Deal Checker.
Auth: email + 4-digit PIN. Sessions stored in DynamoDB.
Admin: separate ADMIN_SECRET token.

User Routes:
  POST /auth/register
  POST /auth/login
  POST /auth/logout
  POST /auth/change-pin
  GET  /user/prefs
  PUT  /user/prefs
  DELETE /user/account
  GET  /stores/search?q=...
  GET  /deals?store_id=...

Admin Routes (Authorization: AdminSecret <secret>):
  GET    /admin/users
  POST   /admin/users                   { email, pin }
  GET    /admin/users/{email}
  DELETE /admin/users/{email}
  POST   /admin/users/{email}/reset-pin { new_pin }
  PUT    /admin/users/{email}/prefs     { prefs }
  DELETE /admin/users/{email}/items
  GET    /admin/scrape-logs
  POST   /admin/scrape-now
  GET    /admin/logs/tail
"""

import json
import os
import hashlib
import secrets
import re
import urllib.request
import urllib.parse
import boto3
from decimal import Decimal
from datetime import datetime, timezone, timedelta

_region         = os.environ.get("PDC_REGION", "us-east-1")
dynamodb        = boto3.resource("dynamodb")
lambda_client   = boto3.client("lambda", region_name=_region)
logs_client     = boto3.client("logs",   region_name=_region)

users_table     = dynamodb.Table(os.environ["USERS_TABLE"])
sessions_table  = dynamodb.Table(os.environ["SESSIONS_TABLE"])
scrape_logs_tbl = dynamodb.Table(os.environ.get("SCRAPE_LOGS_TABLE", "publix-deal-checker-scrape-logs"))

ADMIN_SECRET     = os.environ.get("ADMIN_SECRET", "")
SCRAPER_FUNCTION = os.environ.get("SCRAPER_FUNCTION", "publix-deal-checker-scraper")
LOG_GROUP        = f"/aws/lambda/{SCRAPER_FUNCTION}"

CORS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Content-Type": "application/json",
}

SESSION_TTL_HOURS = 72

SAVINGS_URL = (
    "https://services.publix.com/api/v4/savings"
    "?smImg=235&enImg=368&fallbackImg=false&isMobile=false"
    "&page=1&pageSize=0&includePersonalizedDeals=false"
    "&languageID=1&isWeb=true&getSavingType=AllDeals"
)

DEFAULT_PREFS = {
    "store_id":      "",
    "store_name":    "",
    "store_address": "",
    "notify_email":  "",
    "items":         [],
    "matching":      {"threshold": 75},
    "notifications": {"only_matches": True},
}


# ── helpers ───────────────────────────────────────────────────────────────────

class _Enc(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return int(o) if o == int(o) else float(o)
        return super().default(o)

def ok(body, status=200):
    return {"statusCode": status, "headers": CORS, "body": json.dumps(body, cls=_Enc)}

def err(msg, status=400):
    return {"statusCode": status, "headers": CORS, "body": json.dumps({"error": msg})}

def hash_pin(pin: str) -> str:
    return hashlib.sha256(pin.encode()).hexdigest()

def _to_py(obj):
    if isinstance(obj, Decimal):
        return int(obj) if obj == int(obj) else float(obj)
    if isinstance(obj, dict):  return {k: _to_py(v) for k, v in obj.items()}
    if isinstance(obj, list):  return [_to_py(i) for i in obj]
    return obj

def get_session(event):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    token   = headers.get("authorization", "").replace("Bearer ", "").replace("bearer ", "").strip()
    if not token: return None
    item = sessions_table.get_item(Key={"token": token}).get("Item")
    if not item: return None
    if item.get("expires_at", 0) < int(datetime.now(timezone.utc).timestamp()): return None
    return item

def get_admin_auth(event) -> bool:
    if not ADMIN_SECRET: return False
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    auth    = headers.get("authorization", "").strip()
    # Strip prefix case-insensitively, compare secret case-sensitively
    for prefix in ("AdminSecret ", "adminsecret "):
        if auth.lower().startswith(prefix.lower()):
            return auth[len(prefix):].strip() == ADMIN_SECRET
    # Accept raw secret with no prefix
    return auth == ADMIN_SECRET

def get_body(event) -> dict:
    try:    return json.loads(event.get("body") or "{}")
    except: return {}


# ── auth ──────────────────────────────────────────────────────────────────────

def register(body):
    email = (body.get("email") or "").strip().lower()
    pin   = str(body.get("pin") or "").strip()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return err("Invalid email address.")
    if not re.match(r'^\d{4}$', pin):
        return err("PIN must be exactly 4 digits.")
    if users_table.get_item(Key={"email": email}).get("Item"):
        return err("An account with that email already exists.", 409)
    prefs = {**DEFAULT_PREFS, "notify_email": email}
    users_table.put_item(Item={
        "email":      email,
        "pin_hash":   hash_pin(pin),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "prefs":      prefs,
    })
    return ok({"message": "Account created. Please log in."}, 201)


def login(body):
    email = (body.get("email") or "").strip().lower()
    pin   = str(body.get("pin") or "").strip()
    user  = users_table.get_item(Key={"email": email}).get("Item")
    if not user or user.get("pin_hash") != hash_pin(pin):
        return err("Invalid email or PIN.", 401)
    token      = secrets.token_hex(32)
    expires_at = int((datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)).timestamp())
    sessions_table.put_item(Item={"token": token, "email": email, "expires_at": expires_at})
    prefs = _to_py(user.get("prefs", DEFAULT_PREFS))
    if not prefs.get("notify_email"):
        prefs["notify_email"] = email
    return ok({"token": token, "email": email, "prefs": prefs})


def logout(event):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    token   = headers.get("authorization", "").replace("Bearer ", "").strip()
    if token: sessions_table.delete_item(Key={"token": token})
    return ok({"message": "Logged out."})


def change_pin(event, body):
    sess = get_session(event)
    if not sess: return err("Not authenticated.", 401)
    current_pin = str(body.get("current_pin") or "").strip()
    new_pin     = str(body.get("new_pin") or "").strip()
    if not re.match(r'^\d{4}$', new_pin): return err("New PIN must be 4 digits.")
    user = users_table.get_item(Key={"email": sess["email"]}).get("Item")
    if not user or user.get("pin_hash") != hash_pin(current_pin):
        return err("Current PIN is incorrect.", 401)
    users_table.update_item(Key={"email": sess["email"]},
        UpdateExpression="SET pin_hash = :p",
        ExpressionAttributeValues={":p": hash_pin(new_pin)})
    return ok({"message": "PIN updated."})


# ── user prefs ────────────────────────────────────────────────────────────────

def get_prefs(event):
    sess = get_session(event)
    if not sess: return err("Not authenticated.", 401)
    user = users_table.get_item(Key={"email": sess["email"]}).get("Item")
    if not user: return err("User not found.", 404)
    prefs = _to_py(user.get("prefs", DEFAULT_PREFS))
    if not prefs.get("notify_email"): prefs["notify_email"] = sess["email"]
    return ok({"prefs": prefs, "email": sess["email"]})


def save_prefs(event, body):
    sess = get_session(event)
    if not sess: return err("Not authenticated.", 401)
    incoming = body.get("prefs", body)
    prefs    = {**DEFAULT_PREFS, **incoming}
    ne = (prefs.get("notify_email") or "").strip()
    if ne and not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', ne):
        return err("Invalid notification email address.")
    if not ne: prefs["notify_email"] = sess["email"]
    if isinstance(prefs.get("items"), list): prefs["items"] = prefs["items"][:200]
    users_table.update_item(Key={"email": sess["email"]},
        UpdateExpression="SET prefs = :p",
        ExpressionAttributeValues={":p": prefs})
    return ok({"message": "Preferences saved.", "prefs": prefs})


def delete_account(event):
    sess = get_session(event)
    if not sess: return err("Not authenticated.", 401)
    users_table.delete_item(Key={"email": sess["email"]})
    sessions_table.delete_item(Key={"token": sess.get("token", "")})
    return ok({"message": "Account deleted."})


# ── store search ──────────────────────────────────────────────────────────────

def search_stores(event):
    params  = event.get("queryStringParameters") or {}
    query   = (params.get("q") or "").strip()
    if not query: return err("Missing ?q=")
    url = ("https://services.publix.com/api/v1/storelocation"
           f"?types=G,H,GH,L&numberOfStores=8&includeOpenStoresOnly=false"
           f"&query={urllib.parse.quote(query)}")
    try:
        req = urllib.request.Request(url, headers={"Accept":"application/json","User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=6) as r:
            raw = json.loads(r.read().decode())
    except Exception as e:
        return err(f"Store search failed: {e}", 502)
    stores = []
    for s in (raw if isinstance(raw, list) else raw.get("stores", raw.get("Stores", []))):
        sid = str(s.get("StoreNumber") or s.get("storeNumber") or s.get("id") or "")
        if sid:
            stores.append({
                "id": sid,
                "name":    s.get("Name") or s.get("name") or "",
                "address": s.get("Address") or s.get("address") or "",
                "city":    s.get("City") or s.get("city") or "",
                "state":   s.get("State") or s.get("state") or "",
            })
    return ok({"stores": stores})


# ── deals ─────────────────────────────────────────────────────────────────────

def _parse_deals(raw: dict) -> list[dict]:
    deals = []
    for d in (raw.get("Savings") or []):
        saving_type    = (d.get("savingType") or "WeeklyAd")
        brand_lower    = (d.get("brand") or "").lower()
        title_lower    = (d.get("title") or "").lower()
        is_publix      = brand_lower == "publix" or title_lower.startswith("publix ")
        has_coupon     = bool(d.get("hasCoupon")) or saving_type in ("PrintableCoupon","DigitalCoupon")
        is_stacked     = saving_type == "StackedDeals"
        is_extra       = saving_type == "ExtraSavings"
        deals.append({
            "id":             str(d.get("id", "")),
            "title":          d.get("title", ""),
            "description":    d.get("description", ""),
            "savings":        d.get("savings", ""),
            "save_line":      d.get("additionalDealInfo", ""),
            "fine_print":     d.get("finePrint") or "",
            "brand":          d.get("brand", ""),
            "department":     d.get("department", ""),
            "valid_from":     d.get("wa_startDateFormatted", ""),
            "valid_thru":     d.get("wa_endDateFormatted", ""),
            "image_url":      d.get("enhancedImageUrl") or d.get("imageUrl") or "",
            "saving_type":    saving_type,
            "is_publix_brand":is_publix,
            "has_coupon":     has_coupon,
            "is_stacked":     is_stacked,
            "is_extra":       is_extra,
        })
    return deals


def get_deals(event):
    sess = get_session(event)
    if not sess: return err("Not authenticated.", 401)
    params   = event.get("queryStringParameters") or {}
    store_id = (params.get("store_id") or "").strip()
    if not store_id: return err("Missing store_id parameter.")
    try:
        req = urllib.request.Request(SAVINGS_URL, headers={
            "Accept":      "application/json, text/plain, */*",
            "Origin":      "https://www.publix.com",
            "Referer":     "https://www.publix.com/",
            "publixstore": str(store_id),
            "User-Agent":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = json.loads(resp.read().decode())
    except Exception as e:
        return err(f"Failed to fetch deals from Publix: {e}", 502)

    deals = _parse_deals(raw)
    counts = {
        "total":   len(deals),
        "weekly":  sum(1 for d in deals if d["saving_type"] == "WeeklyAd"),
        "extra":   sum(1 for d in deals if d["is_extra"]),
        "stacked": sum(1 for d in deals if d["is_stacked"]),
        "coupon":  sum(1 for d in deals if d["has_coupon"]),
        "publix":  sum(1 for d in deals if d["is_publix_brand"]),
    }
    # Per-department counts
    dept_counts = {}
    for d in deals:
        dept = (d.get("department") or "Other").strip()
        dept_counts[dept] = dept_counts.get(dept, 0) + 1

    return ok({
        "deals":       deals,
        "total":       len(deals),
        "store_id":    store_id,
        "updated_at":  raw.get("WeeklyAdLatestUpdatedDateTime", ""),
        "counts":      counts,
        "dept_counts": dept_counts,
    })


# ── admin: scrape logs ────────────────────────────────────────────────────────

def get_scrape_logs(event):
    if not get_admin_auth(event): return err("Unauthorized.", 401)
    try:
        resp  = scrape_logs_tbl.scan(Limit=50)
        items = _to_py(resp.get("Items", []))
        items.sort(key=lambda x: x.get("started_at", ""), reverse=True)
        return ok({"logs": items[:15]})
    except Exception as e:
        return err(f"Could not fetch scrape logs: {e}", 500)


def invoke_scraper(event):
    if not get_admin_auth(event): return err("Unauthorized.", 401)
    try:
        lambda_client.invoke(FunctionName=SCRAPER_FUNCTION, InvocationType="Event")
        return ok({"message": f"Scraper invoked. Check logs in ~30 seconds."})
    except Exception as e:
        return err(f"Failed to invoke scraper: {e}", 500)


def get_log_tail(event):
    if not get_admin_auth(event): return err("Unauthorized.", 401)
    try:
        streams = logs_client.describe_log_streams(
            logGroupName=LOG_GROUP, orderBy="LastEventTime",
            descending=True, limit=3,
        ).get("logStreams", [])
        if not streams: return ok({"lines": [], "stream": None})

        all_lines = []
        for stream_info in streams[:2]:
            stream = stream_info["logStreamName"]
            events = logs_client.get_log_events(
                logGroupName=LOG_GROUP, logStreamName=stream,
                limit=150, startFromHead=False,
            ).get("events", [])
            for e in events:
                ts  = datetime.fromtimestamp(e["timestamp"]/1000, tz=timezone.utc)
                all_lines.append({"ts": ts.isoformat(), "msg": e["message"].rstrip("\n")})

        all_lines.sort(key=lambda x: x["ts"])
        return ok({"lines": all_lines[-150:], "stream": streams[0]["logStreamName"]})
    except Exception as e:
        return err(f"Could not fetch logs: {e}", 500)


# ── admin: user management ────────────────────────────────────────────────────

def admin_list_users(event):
    if not get_admin_auth(event): return err("Unauthorized.", 401)
    try:
        items, resp = [], users_table.scan()
        items.extend(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = users_table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
            items.extend(resp.get("Items", []))
        users = []
        for u in _to_py(items):
            p = u.get("prefs") or {}
            users.append({
                "email":        u["email"],
                "created_at":   u.get("created_at", ""),
                "store_id":     p.get("store_id", ""),
                "store_name":   p.get("store_name", ""),
                "notify_email": p.get("notify_email") or u["email"],
                "item_count":   len(p.get("items") or []),
                "items":        p.get("items") or [],
                "threshold":    (p.get("matching") or {}).get("threshold", 75),
            })
        users.sort(key=lambda x: x["email"])
        return ok({"users": users, "total": len(users)})
    except Exception as e:
        return err(f"Failed: {e}", 500)


def admin_get_user(event, email: str):
    if not get_admin_auth(event): return err("Unauthorized.", 401)
    user = users_table.get_item(Key={"email": email}).get("Item")
    if not user: return err("User not found.", 404)
    safe = _to_py(user)
    safe.pop("pin_hash", None)
    return ok({"user": safe})


def admin_create_user(event, body):
    if not get_admin_auth(event): return err("Unauthorized.", 401)
    return register(body)


def admin_delete_user(event, email: str):
    if not get_admin_auth(event): return err("Unauthorized.", 401)
    if not email: return err("Missing email.")
    users_table.delete_item(Key={"email": email})
    return ok({"message": f"User {email} deleted."})


def admin_reset_pin(event, body, email: str):
    if not get_admin_auth(event): return err("Unauthorized.", 401)
    new_pin = str(body.get("new_pin") or "").strip()
    if not re.match(r'^\d{4}$', new_pin): return err("New PIN must be 4 digits.")
    if not users_table.get_item(Key={"email": email}).get("Item"):
        return err("User not found.", 404)
    users_table.update_item(Key={"email": email},
        UpdateExpression="SET pin_hash = :p",
        ExpressionAttributeValues={":p": hash_pin(new_pin)})
    return ok({"message": f"PIN reset for {email}."})


def admin_reset_email(event, body, email: str):
    if not get_admin_auth(event): return err("Unauthorized.", 401)
    new_email = (body.get("new_email") or "").strip().lower()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', new_email):
        return err("Invalid email address.")
    user = users_table.get_item(Key={"email": email}).get("Item")
    if not user: return err("User not found.", 404)
    # Create new record, delete old
    new_item = {**user, "email": new_email}
    users_table.put_item(Item=new_item)
    users_table.delete_item(Key={"email": email})
    return ok({"message": f"Email changed from {email} to {new_email}."})


def admin_patch_prefs(event, body, email: str):
    if not get_admin_auth(event): return err("Unauthorized.", 401)
    user = users_table.get_item(Key={"email": email}).get("Item")
    if not user: return err("User not found.", 404)
    existing = _to_py(user.get("prefs", DEFAULT_PREFS))
    merged   = {**existing, **(body.get("prefs", body))}
    users_table.update_item(Key={"email": email},
        UpdateExpression="SET prefs = :p",
        ExpressionAttributeValues={":p": merged})
    return ok({"message": f"Prefs updated for {email}.", "prefs": merged})


def admin_clear_items(event, email: str):
    if not get_admin_auth(event): return err("Unauthorized.", 401)
    user = users_table.get_item(Key={"email": email}).get("Item")
    if not user: return err("User not found.", 404)
    prefs = _to_py(user.get("prefs", DEFAULT_PREFS))
    prefs["items"] = []
    users_table.update_item(Key={"email": email},
        UpdateExpression="SET prefs = :p",
        ExpressionAttributeValues={":p": prefs})
    return ok({"message": f"Items cleared for {email}."})


# ── router ────────────────────────────────────────────────────────────────────

def handler(event, context):
    http_ctx = event.get("requestContext", {}).get("http", {})
    method   = http_ctx.get("method") or event.get("httpMethod", "GET")
    path     = http_ctx.get("path")   or event.get("rawPath") or event.get("path", "")
    body     = get_body(event)

    if method == "OPTIONS":
        return {"statusCode": 200, "headers": CORS, "body": ""}

    # User routes
    if path == "/auth/register"   and method == "POST":   return register(body)
    if path == "/auth/login"      and method == "POST":   return login(body)
    if path == "/auth/logout"     and method == "POST":   return logout(event)
    if path == "/auth/change-pin" and method == "POST":   return change_pin(event, body)
    if path == "/user/prefs"      and method == "GET":    return get_prefs(event)
    if path == "/user/prefs"      and method == "PUT":    return save_prefs(event, body)
    if path == "/user/account"    and method == "DELETE": return delete_account(event)
    if path == "/stores/search"   and method == "GET":    return search_stores(event)
    if path == "/deals"           and method == "GET":    return get_deals(event)

    # Admin fixed routes
    if path == "/admin/users"       and method == "GET":  return admin_list_users(event)
    if path == "/admin/users"       and method == "POST": return admin_create_user(event, body)
    if path == "/admin/scrape-logs" and method == "GET":  return get_scrape_logs(event)
    if path == "/admin/scrape-now"  and method == "POST": return invoke_scraper(event)
    if path == "/admin/logs/tail"   and method == "GET":  return get_log_tail(event)

    # Admin parameterised routes  /admin/users/{email}[/action]
    if path.startswith("/admin/users/"):
        rest   = path[len("/admin/users/"):]
        parts  = rest.split("/", 1)
        uemail = urllib.parse.unquote(parts[0])
        action = parts[1] if len(parts) > 1 else ""
        if not action and method == "GET":    return admin_get_user(event, uemail)
        if not action and method == "DELETE": return admin_delete_user(event, uemail)
        if action == "reset-pin"  and method == "POST": return admin_reset_pin(event, body, uemail)
        if action == "reset-email"and method == "POST": return admin_reset_email(event, body, uemail)
        if action == "prefs"      and method == "PUT":  return admin_patch_prefs(event, body, uemail)
        if action == "items"      and method == "DELETE": return admin_clear_items(event, uemail)

    if path == "/user/test-email" and method == "POST": return send_test_email(event)

    # Debug: echo back auth headers (remove after debugging)
    if path == "/admin/debug" and method == "GET":
        headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
        return ok({
            "auth_header": headers.get("authorization","(none)"),
            "admin_secret_set": bool(ADMIN_SECRET),
            "admin_secret_len": len(ADMIN_SECRET),
            "admin_secret_prefix": ADMIN_SECRET[:4] + "..." if len(ADMIN_SECRET) > 4 else ADMIN_SECRET,
            "match": get_admin_auth(event),
        })

    return err("Not found.", 404)


# ── test email ────────────────────────────────────────────────────────────────

def send_test_email(event):
    """POST /user/test-email — sends a test alert to the user's notify_email."""
    sess = get_session(event)
    if not sess: return err("Not authenticated.", 401)
    user = users_table.get_item(Key={"email": sess["email"]}).get("Item")
    if not user: return err("User not found.", 404)
    prefs        = _to_py(user.get("prefs", DEFAULT_PREFS))
    notify_email = (prefs.get("notify_email") or sess["email"]).strip()

    resend_key  = os.environ.get("RESEND_API_KEY","")
    resend_from = (f"{os.environ.get('RESEND_FROM_NAME','Publix Alerts')} "
                   f"<{os.environ.get('RESEND_FROM_ADDR','onboarding@resend.dev')}>")
    if not resend_key:
        return err("Resend API key not configured.", 500)

    try:
        import resend as _resend
        _resend.api_key = resend_key
        _resend.Emails.send({
            "from":    resend_from,
            "to":      [notify_email],
            "subject": "✅ Publix Deal Checker — test email",
            "html":    f"""<html><body style="font-family:Arial,sans-serif;max-width:600px;margin:40px auto;color:#333;">
  <div style="background:#1a6b3c;color:white;padding:24px;border-radius:8px 8px 0 0;">
    <h2 style="margin:0;">✅ Test Email</h2>
    <p style="margin:4px 0 0;opacity:.8;">Publix Deal Checker notifications are working.</p>
  </div>
  <div style="background:white;border:1px solid #ddd;border-top:none;padding:24px;border-radius:0 0 8px 8px;">
    <p>This is a test message sent to <strong>{notify_email}</strong>.</p>
    <p style="color:#888;font-size:13px;margin-top:16px;">Sent from your Publix Deal Checker account: {sess["email"]}</p>
  </div>
</body></html>""",
        })
        return ok({"message": f"Test email sent to {notify_email}."})
    except Exception as e:
        return err(f"Failed to send email: {e}", 500)
