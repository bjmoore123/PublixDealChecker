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
auth_logs_tbl   = dynamodb.Table(os.environ.get("AUTH_LOGS_TABLE",  "publix-deal-checker-auth-logs"))
app_logs_tbl    = dynamodb.Table(os.environ.get("APP_LOGS_TABLE",   "publix-deal-checker-app-logs"))

# Strip any accidental whitespace/newlines that can sneak in via Lambda env vars
ADMIN_SECRET     = (os.environ.get("ADMIN_SECRET", "") or "").strip()
SCRAPER_FUNCTION = os.environ.get("SCRAPER_FUNCTION", "publix-deal-checker-scraper")
LOG_GROUP        = f"/aws/lambda/{SCRAPER_FUNCTION}"

CORS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Content-Type": "application/json",
}

SESSION_TTL_HOURS = 72

_SAVINGS_BASE = (
    "https://services.publix.com/api/v4/savings"
    "?smImg=235&enImg=368&fallbackImg=false&isMobile=false"
    "&page=1&pageSize=0&includePersonalizedDeals=false"
    "&languageID=1&isWeb=true"
)
# KEY: publixstore must be sent as a REQUEST HEADER (not query param)
# WeeklyAd and AllDeals are separate pools that must both be fetched
SAVINGS_URL_WEEKLY  = _SAVINGS_BASE + "&getSavingType=WeeklyAd"
SAVINGS_URL_COUPONS = _SAVINGS_BASE + "&getSavingType=AllDeals"
SAVINGS_URL = SAVINGS_URL_COUPONS  # legacy alias

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


# ── helpers ───────────────────────────────────────────────────────────────────

class _Enc(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return int(o) if o == int(o) else float(o)
        return super().default(o)

def ok(body, status=200):
    return {"statusCode": status, "headers": CORS, "body": json.dumps(body, cls=_Enc)}

def err(msg, status=400, _event=None, _path=None, _method=None):
    if status >= 400 and status != 401 and status != 404:
        # Log 4xx/5xx errors (skip auth failures and 404s to reduce noise)
        try:
            _log_app_event("api", "error" if status >= 500 else "warn",
                           status=status, message=str(msg)[:300],
                           path=_path or "", method=_method or "")
        except Exception:
            pass
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
            candidate = auth[len(prefix):].strip()
            return candidate == ADMIN_SECRET
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


# ── auth event logging ───────────────────────────────────────────────────────

def _get_client_ip(event: dict) -> str:
    """Extract real client IP from API Gateway event."""
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    for h in ("x-forwarded-for", "x-real-ip"):
        v = headers.get(h, "")
        if v:
            return v.split(",")[0].strip()
    return (event.get("requestContext", {})
                 .get("http", {})
                 .get("sourceIp", "unknown"))


def _geo_lookup(ip: str) -> dict:
    """Look up country/city for an IP using ip-api.com (free, no key needed)."""
    if not ip or ip in ("unknown", "127.0.0.1"):
        return {}
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=country,regionName,city,status",
            headers={"User-Agent": "publix-deal-checker/1.0"},
        )
        with urllib.request.urlopen(req, timeout=3) as r:
            d = json.loads(r.read())
        if d.get("status") == "success":
            return {"country": d.get("country",""), "region": d.get("regionName",""), "city": d.get("city","")}
    except Exception:
        pass
    return {}


def _log_auth_event(event: dict, email: str, success: bool, reason: str = ""):
    """Write a login attempt record to the auth_logs DynamoDB table."""
    try:
        ip  = _get_client_ip(event)
        geo = _geo_lookup(ip)
        headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
        ua  = headers.get("user-agent", "")[:200]
        now = datetime.now(timezone.utc).isoformat()
        auth_logs_tbl.put_item(Item={
            "log_id":    f"{now}#{secrets.token_hex(4)}",
            "ts":        now,
            "email":     email or "(unknown)",
            "success":   success,
            "ip":        ip,
            "country":   geo.get("country", ""),
            "region":    geo.get("region", ""),
            "city":      geo.get("city", ""),
            "user_agent": ua,
            "reason":    reason,
        })
    except Exception:
        pass  # never let logging break auth


def _log_app_event(source: str, level: str = "info", **fields):
    """Write a structured application log entry to app_logs DynamoDB table.
    source: 'frontend' | 'api' | 'email' | 'cache'
    Never raises — logging must never break the main request flow.
    """
    try:
        now = datetime.now(timezone.utc).isoformat()
        item = {
            "log_id":  f"{now}#{secrets.token_hex(4)}",
            "ts":      now,
            "source":  source,
            "level":   level,
            **{k: v for k, v in fields.items() if v is not None},
        }
        app_logs_tbl.put_item(Item=item)
    except Exception:
        pass


def login(body):
    email = (body.get("email") or "").strip().lower()
    pin   = str(body.get("pin") or "").strip()
    user  = users_table.get_item(Key={"email": email}).get("Item")
    if not user or user.get("pin_hash") != hash_pin(pin):
        # We need the event to log it — login() is called from handler() which has it
        # We'll log via a thread-local trick: store event on body dict
        _log_auth_event(body.get("__event__", {}), email, False, "bad_pin")
        return err("Invalid email or PIN.", 401)
    token      = secrets.token_hex(32)
    expires_at = int((datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)).timestamp())
    sessions_table.put_item(Item={"token": token, "email": email, "expires_at": expires_at})
    _log_auth_event(body.get("__event__", {}), email, True)
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

def _parse_store_feature(f: dict) -> dict:
    """Parse a GeoJSON feature from the storelocator API into a clean store dict."""
    p    = f.get("properties") or f  # single-store endpoint returns props directly
    geo  = f.get("geometry", {}).get("coordinates", [None, None])
    addr = p.get("address") or {}
    phones = p.get("phoneNumbers") or {}
    img    = p.get("image") or {}
    hours  = p.get("hours") or []
    # Format today's hours (first entry = today)
    hours_str = ""
    if hours:
        h = hours[0]
        if h.get("isClosed"):
            hours_str = "Closed today"
        elif h.get("isOpen24Hours"):
            hours_str = "Open 24 hours"
        else:
            def fmt_time(iso):
                try:
                    from datetime import datetime
                    t = datetime.fromisoformat(iso)
                    return t.strftime("%-I:%M %p").replace(":00 ", " ")
                except Exception:
                    return iso[11:16] if len(iso) > 15 else iso
            hours_str = f"{fmt_time(h.get('openTime',''))} – {fmt_time(h.get('closeTime',''))}"
    street  = addr.get("streetAddress","")
    city    = addr.get("city","")
    state   = addr.get("state","")
    zipcode = addr.get("zip","")
    address_full = f"{street}, {city}, {state} {zipcode}".strip(", ")
    return {
        "id":           str(p.get("storeNumber") or ""),
        "name":         p.get("name") or "",
        "short_name":   p.get("shortName") or "",
        "street":       street,
        "city":         city,
        "state":        state,
        "zip":          zipcode,
        "address":      address_full,
        "phone":        phones.get("Store",""),
        "pharmacy_phone": phones.get("Pharmacy",""),
        "hours_today":  hours_str,
        "hours_raw":    hours,
        "lat":          geo[0] if geo else None,
        "lng":          geo[1] if geo else None,
        "img_thumb":    img.get("thumbnail",""),
        "img_hero":     img.get("hero",""),
        "distance":     p.get("distance"),
    }


# Headers required by Publix storelocator API (CORS-protected, needs Origin)
_STORE_HDRS = {
    "Accept":          "application/geo+json",
    "Accept-Encoding": "gzip, deflate",
    "Origin":          "https://www.publix.com",
    "Referer":         "https://www.publix.com/",
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}

def _store_fetch(url: str, timeout: int = 8) -> dict:
    """Fetch from storelocator API, handling gzip transparently."""
    import gzip as _gzip
    req = urllib.request.Request(url, headers=_STORE_HDRS)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
        if r.headers.get("Content-Encoding") == "gzip":
            body = _gzip.decompress(body)
        return json.loads(body)


def search_stores(event):
    params  = event.get("queryStringParameters") or {}
    query   = (params.get("q") or "").strip()
    if not query: return err("Missing ?q=")

    # Detect query type
    is_store_num = bool(re.match(r'^\d{3,6}$', query))
    is_zip       = bool(re.match(r'^\d{5}$', query))

    if is_store_num:
        # Single store by number — returns GeoJSON with geo+json Accept header
        url = (f"https://services.publix.com/storelocator/api/v1/stores/"
               f"?types=R,G,H,N,S&count=1&distance=1000&includeOpenAndCloseDates=true"
               f"&storeNumber={urllib.parse.quote(query)}&includeStore=true&isWebsite=true")
        try:
            raw  = _store_fetch(url)
            features = raw.get("features", [])
            stores = [_parse_store_feature(f) for f in features if f.get("properties",{}).get("storeNumber")]
            return ok({"stores": stores[:1]})
        except Exception as e:
            return err(f"Store lookup failed: {e}", 502)
    else:
        param = "zip" if is_zip else "city"
        url = (f"https://services.publix.com/storelocator/api/v1/stores/"
               f"?types=R,G,H,N,S&count=10&distance=50&includeOpenAndCloseDates=true"
               f"&{param}={urllib.parse.quote(query)}&isWebsite=true")
        try:
            raw = _store_fetch(url)
        except Exception as e:
            return err(f"Store search failed: {e}", 502)
        features = raw.get("features", [])
        stores = [_parse_store_feature(f) for f in features if f.get("properties",{}).get("storeNumber")]
        return ok({"stores": stores[:10]})


# ── deals ─────────────────────────────────────────────────────────────────────

def _enrich_deal(d: dict) -> dict:
    """Add computed boolean fields to a deal dict (works on both cached and raw API dicts)."""
    saving_type = (d.get("saving_type") or d.get("savingType") or "WeeklyAd")
    brand_lower = (d.get("brand") or "").lower()
    title_lower = (d.get("title") or "").lower()
    savings_str = (d.get("savings") or "").lower()
    categories  = d.get("categories") or []
    is_publix   = brand_lower == "publix" or title_lower.startswith("publix ")
    has_coupon  = bool(d.get("has_coupon") or d.get("hasCoupon")) or saving_type in ("PrintableCoupon", "DigitalCoupon")
    is_stacked  = saving_type == "StackedDeals"
    is_extra    = saving_type == "ExtraSavings"
    import re as _re
    _bogo_text = title_lower + " " + savings_str
    is_bogo     = (
        "bogo" in categories
        or bool(_re.search(r"b[12]g1|buy \d.{0,8}get \d|buy one.{0,10}get one", _bogo_text))
    )
    return {**d,
        "saving_type":     saving_type,
        "is_bogo":         is_bogo,
        "categories":      categories,
        "is_publix_brand": is_publix,
        "has_coupon":      has_coupon,
        "is_stacked":      is_stacked,
        "is_extra":        is_extra,
    }


def _parse_deal(d: dict) -> dict:
    """Re-enrich a deal that was previously serialised to the DynamoDB cache."""
    return _enrich_deal(d)


def _parse_deals_raw(raw: dict) -> list[dict]:
    """Parse deals straight from the live Publix savings API response."""
    deals = []
    for d in (raw.get("Savings") or []):
        saving_type = (d.get("savingType") or "WeeklyAd")
        base = {
            "id":          str(d.get("id", "")),
            "title":       d.get("title", ""),
            "description": d.get("description", ""),
            "savings":     d.get("savings", ""),
            "save_line":   d.get("additionalDealInfo", ""),
            "fine_print":  d.get("finePrint") or "",
            "brand":       d.get("brand", ""),
            "department":  d.get("department", ""),
            "valid_from":  d.get("wa_startDateFormatted", ""),
            "valid_thru":  d.get("wa_endDateFormatted", ""),
            "image_url":   d.get("enhancedImageUrl") or d.get("imageUrl") or "",
            "saving_type": saving_type,
            "coupon_id":   str(d.get("dcId")) if d.get("dcId") else "",
            "categories":  d.get("categories") or [],
        }
        deals.append(_enrich_deal(base))
    return deals


# Keep old name as alias so the scraper lambda (which imports nothing from here) is unaffected
def _parse_deals(raw: dict) -> list[dict]:
    return _parse_deals_raw(raw)


def get_deals(event):
    sess = get_session(event)
    if not sess: return err("Not authenticated.", 401)
    params   = event.get("queryStringParameters") or {}
    store_id = (params.get("store_id") or "").strip()
    if not store_id: return err("Missing store_id parameter.")

    # Prefer the DynamoDB cache written by the weekly scraper
    deals_table_obj = dynamodb.Table(os.environ["DEALS_TABLE"])
    cached = deals_table_obj.get_item(Key={"store_id": store_id}).get("Item")
    if cached:
        num_chunks = int(cached.get("num_chunks", 0))
        updated_at = str(cached.get("fetched_at", ""))
        if num_chunks > 0:
            raw_deals = []
            for i in range(num_chunks):
                chunk_row = deals_table_obj.get_item(Key={"store_id": f"{store_id}#{i}"}).get("Item")
                if chunk_row:
                    raw_deals.extend(json.loads(chunk_row.get("deals", "[]")))
        else:
            # Legacy single-row format
            raw_deals = json.loads(cached.get("deals", "[]"))
        deals = [_parse_deal(d) for d in raw_deals]
        _log_app_event("cache", "info", hit=True,  store_id=store_id, endpoint="/deals", deal_count=len(deals))
    else:
        # No cache yet — fall back to a live fetch so first-time users see data
        _hdrs = {
            "Accept":      "application/json, text/plain, */*",
            "Origin":      "https://www.publix.com",
            "Referer":     "https://www.publix.com/",
            "publixstore": str(store_id),
            "User-Agent":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        deals = []
        seen_ids = set()
        updated_at = ""
        for _url in [SAVINGS_URL_WEEKLY, SAVINGS_URL_COUPONS]:
            try:
                req = urllib.request.Request(_url, headers=_hdrs)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    raw = json.loads(resp.read().decode())
                if not updated_at:
                    updated_at = raw.get("WeeklyAdLatestUpdatedDateTime", "")
                    _log_app_event("cache", "warn", hit=False, store_id=store_id, endpoint="/deals",
                                   message="cache miss — live fetch used")
                for d in _parse_deals_raw(raw):
                    if d["id"] not in seen_ids:
                        seen_ids.add(d["id"])
                        deals.append(d)
            except Exception as e:
                if not deals:
                    _log_app_event("cache", "warn", hit=False, store_id=store_id, endpoint="/deals",
                                   message=f"Live fetch failed: {e}")
                    return err(f"No cached deals and live fetch failed: {e}", 502)

    counts = {
        "total":   len(deals),
        "weekly":  sum(1 for d in deals if d["saving_type"] == "WeeklyAd" and not d.get("is_bogo")),
        "extra":   sum(1 for d in deals if d["is_extra"]),
        "stacked": sum(1 for d in deals if d["is_stacked"]),
        "coupon":  sum(1 for d in deals if d["has_coupon"]),
        "publix":  sum(1 for d in deals if d["is_publix_brand"]),
    }

    dept_counts: dict = {}
    for d in deals:
        dept = (d.get("department") or "Other").strip()
        dept_counts[dept] = dept_counts.get(dept, 0) + 1

    # Unique saving_type values present in this week's data (drives dynamic Savings filter)
    saving_types = sorted({d["saving_type"] for d in deals if d.get("saving_type")})

    return ok({
        "deals":        deals,
        "total":        len(deals),
        "store_id":     store_id,
        "updated_at":   updated_at,
        "counts":       counts,
        "dept_counts":  dept_counts,
        "saving_types": saving_types,
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
            if u.get("email") == "__meta__": continue
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
    # Track deletion count in metadata record
    try:
        users_table.update_item(
            Key={"email": "__meta__"},
            UpdateExpression="ADD deleted_count :one SET last_deleted_at = :ts",
            ExpressionAttributeValues={":one": 1, ":ts": datetime.now(timezone.utc).isoformat()}
        )
    except Exception:
        pass
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



def admin_stats(event):
    if not get_admin_auth(event): return err("Unauthorized.", 401)

    # Scan all users
    items, resp = [], users_table.scan()
    items.extend(resp.get("Items", []))
    while "LastEvaluatedKey" in resp:
        resp = users_table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
        items.extend(resp.get("Items", []))
    users = [u for u in _to_py(items) if u.get("email") != "__meta__"]

    total = len(users)

    # Users by join date (by month)
    from collections import Counter, defaultdict
    by_month = Counter()
    for u in users:
        ts = u.get("created_at", "")
        if ts:
            by_month[ts[:7]] += 1  # "YYYY-MM"

    # Geography: group by store city/name
    by_store = Counter()
    for u in users:
        p = u.get("prefs") or {}
        name = p.get("store_name") or ""
        sid  = p.get("store_id") or ""
        if name:
            # Extract city: store names are like "Publix Super Market at Shoppes at XYZ, Asheville, NC"
            # Try to get last part after last comma as city
            parts = [x.strip() for x in name.split(",")]
            city = parts[-2] if len(parts) >= 2 else (parts[-1] if parts else sid or "Unknown")
            by_store[city] += 1
        elif sid:
            by_store[f"Store #{sid}"] += 1
        else:
            by_store["No store set"] += 1

    # Average list items
    item_counts = [len((u.get("prefs") or {}).get("items") or []) for u in users]
    avg_items = round(sum(item_counts) / total, 1) if total else 0

    # Popular items across all users
    all_items = Counter()
    for u in users:
        p = u.get("prefs") or {}
        for item in (p.get("items") or []):
            if item and isinstance(item, str):
                all_items[item.strip().lower()] += 1

    popular = [{"item": k, "count": v} for k, v in all_items.most_common(25)]

    # Users with no items
    no_items = sum(1 for c in item_counts if c == 0)

    # Fetch deletion metadata
    meta = users_table.get_item(Key={"email": "__meta__"}).get("Item") or {}
    meta = _to_py(meta)
    deleted_count = int(meta.get("deleted_count", 0))

    return ok({
        "total_users":     total,
        "deleted_users":   deleted_count,
        "avg_items":       avg_items,
        "no_items_count":  no_items,
        "by_month":        [{"month": k, "count": v} for k, v in sorted(by_month.items())],
        "by_geography":    [{"location": k, "count": v} for k, v in by_store.most_common(20)],
        "popular_items":   popular,
    })


# ── admin: auth logs ─────────────────────────────────────────────────────────

def get_auth_logs(event):
    if not get_admin_auth(event): return err("Unauthorized.", 401)
    try:
        params  = event.get("queryStringParameters") or {}
        limit   = min(int(params.get("limit", 100)), 500)
        resp    = auth_logs_tbl.scan(Limit=limit)
        items   = _to_py(resp.get("Items", []))
        items.sort(key=lambda x: x.get("ts", ""), reverse=True)
        return ok({"logs": items[:limit]})
    except Exception as e:
        return err(f"Could not fetch auth logs: {e}", 500)


# ── admin: app/api logs ───────────────────────────────────────────────────────

def get_app_logs(event):
    if not get_admin_auth(event): return err("Unauthorized.", 401)
    try:
        params  = event.get("queryStringParameters") or {}
        limit   = min(int(params.get("limit", 100)), 500)
        resp    = app_logs_tbl.scan(Limit=limit)
        items   = _to_py(resp.get("Items", []))
        items.sort(key=lambda x: x.get("ts", ""), reverse=True)
        return ok({"logs": items[:limit]})
    except Exception as e:
        return err(f"Could not fetch app logs: {e}", 500)


def log_frontend_error(event, body):
    """POST /log/error — receive frontend JS error reports."""
    try:
        ip  = _get_client_ip(event)
        now = datetime.now(timezone.utc).isoformat()
        app_logs_tbl.put_item(Item={
            "log_id":  f"{now}#{secrets.token_hex(4)}",
            "ts":      now,
            "source":  "frontend",
            "level":   body.get("level", "error"),
            "message": str(body.get("message", ""))[:500],
            "stack":   str(body.get("stack", ""))[:1000],
            "url":     str(body.get("url", ""))[:200],
            "ip":      ip,
        })
        return ok({"message": "Logged."})
    except Exception as e:
        return err(f"Log write failed: {e}", 500)


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
    if path == "/auth/login"      and method == "POST":
        body["__event__"] = event
        return login(body)
    if path == "/auth/logout"     and method == "POST":   return logout(event)
    if path == "/auth/change-pin" and method == "POST":   return change_pin(event, body)
    if path == "/user/prefs"      and method == "GET":    return get_prefs(event)
    if path == "/user/prefs"      and method == "PUT":    return save_prefs(event, body)
    if path == "/user/account"    and method == "DELETE": return delete_account(event)
    if path == "/user/test-email" and method == "POST":   return send_test_email(event)
    if path == "/stores/search"   and method == "GET":    return search_stores(event)
    if path == "/deals"           and method == "GET":    return get_deals(event)

    # Admin fixed routes
    if path == "/admin/users"       and method == "GET":  return admin_list_users(event)
    if path == "/admin/users"       and method == "POST": return admin_create_user(event, body)
    if path == "/admin/scrape-logs" and method == "GET":  return get_scrape_logs(event)
    if path == "/admin/scrape-now"  and method == "POST": return invoke_scraper(event)
    if path == "/admin/logs/tail"   and method == "GET":  return get_log_tail(event)
    if path == "/admin/stats"        and method == "GET":  return admin_stats(event)
    if path == "/admin/auth-logs"    and method == "GET":  return get_auth_logs(event)
    if path == "/admin/app-logs"     and method == "GET":  return get_app_logs(event)
    if path == "/log/error"          and method == "POST": return log_frontend_error(event, body)

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
        _log_app_event("email", "info", ok=True,
                       to=notify_email, subject="test-email",
                       trigger="manual", user=sess["email"])
        return ok({"message": f"Test email sent to {notify_email}."})
    except Exception as e:
        _log_app_event("email", "error", ok=False,
                       to=notify_email, subject="test-email",
                       trigger="manual", user=sess["email"], message=str(e)[:200])
        return err(f"Failed to send email: {e}", 500)
