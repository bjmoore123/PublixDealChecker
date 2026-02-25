"""
scraper/main.py  (v4 - serverless Lambda)

Lambda entry point. Triggered by EventBridge weekly.
Writes a scrape-job summary record to DynamoDB after each run.
Uses per-user notify_email for alert delivery.
"""

import json
import os
import boto3
import resend
from datetime import date, datetime, timezone
from decimal import Decimal

from scraper import get_deals
from matcher import match_deals_for_user

# ── Config ────────────────────────────────────────────────────────────────────

AWS_REGION      = os.environ.get("PDC_REGION", os.environ.get("AWS_REGION", "us-east-1"))
USERS_TABLE     = os.environ["USERS_TABLE"]
DEALS_TABLE     = os.environ["DEALS_TABLE"]
SCRAPE_LOGS_TBL = os.environ.get("SCRAPE_LOGS_TABLE", "publix-deal-checker-scrape-logs")

resend.api_key = os.environ["RESEND_API_KEY"]
RESEND_FROM    = (
    f"{os.environ.get('RESEND_FROM_NAME','Publix Alerts')} "
    f"<{os.environ.get('RESEND_FROM_ADDR','onboarding@resend.dev')}>"
)

dynamodb        = boto3.resource("dynamodb", region_name=AWS_REGION)
users_table     = dynamodb.Table(USERS_TABLE)
deals_table     = dynamodb.Table(DEALS_TABLE)
scrape_logs_tbl = dynamodb.Table(SCRAPE_LOGS_TBL)


# ── DynamoDB helpers ──────────────────────────────────────────────────────────

def to_python(obj):
    if isinstance(obj, Decimal):
        return int(obj) if obj == int(obj) else float(obj)
    if isinstance(obj, dict):  return {k: to_python(v) for k, v in obj.items()}
    if isinstance(obj, list):  return [to_python(i) for i in obj]
    return obj


def get_all_users() -> list[dict]:
    items, resp = [], users_table.scan(ProjectionExpression="email, prefs")
    items.extend(resp.get("Items", []))
    while "LastEvaluatedKey" in resp:
        resp = users_table.scan(
            ProjectionExpression="email, prefs",
            ExclusiveStartKey=resp["LastEvaluatedKey"],
        )
        items.extend(resp.get("Items", []))
    return [to_python(u) for u in items]


def cache_deals(store_id: str, deals: list[dict]):
    deals_table.put_item(Item={
        "store_id":   store_id,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "deals":      json.dumps(deals),
        "count":      len(deals),
    })


def write_scrape_log(log: dict):
    """Persist scrape job summary to DynamoDB."""
    try:
        scrape_logs_tbl.put_item(Item=log)
    except Exception as e:
        print(f"  WARNING: Could not write scrape log: {e}")


# ── Email ─────────────────────────────────────────────────────────────────────

def build_html(matches: list[dict], store_id: str, store_name: str) -> str:
    today = date.today().strftime("%B %d, %Y")
    rows  = ""
    for m in matches:
        img = (f'<img src="{m["image_url"]}" width="56" height="56" '
               f'style="object-fit:contain;border-radius:4px;border:1px solid #eee;" alt="">'
               if m.get("image_url") else "")
        valid = ""
        if m.get("valid_from") or m.get("valid_thru"):
            valid = f'<div style="font-size:11px;color:#888;">Valid {m.get("valid_from","")}–{m.get("valid_thru","")}</div>'
        rows += f"""
        <tr style="border-bottom:1px solid #eee;">
          <td style="padding:10px 8px;width:64px;">{img}</td>
          <td style="padding:10px 8px;">
            <div style="font-size:11px;color:#888;text-transform:uppercase;margin-bottom:2px;">{m.get('my_item','')}</div>
            <div style="font-weight:600;">{m['deal_name']}</div>
            {f'<div style="font-size:12px;color:#555;">{m["description"]}</div>' if m.get('description') else ''}
            {f'<div style="font-size:11px;color:#999;">{m["fine_print"]}</div>' if m.get('fine_print') else ''}
            {valid}
          </td>
          <td style="padding:10px 8px;text-align:right;white-space:nowrap;">
            <div style="font-size:20px;font-weight:700;color:#1a6b3c;">{m.get('savings','')}</div>
            {f'<div style="font-size:12px;color:#e76f51;">{m["save_line"]}</div>' if m.get('save_line') else ''}
          </td>
        </tr>"""

    return f"""<html><body style="font-family:Arial,sans-serif;max-width:680px;margin:0 auto;color:#333;">
      <div style="background:#1a6b3c;color:white;padding:20px 24px;border-radius:8px 8px 0 0;">
        <h2 style="margin:0;">&#x1F6D2; Publix Deal Alert</h2>
        <p style="margin:4px 0 0;opacity:.85;">{today} &nbsp;&middot;&nbsp; {store_name or f'Store #{store_id}'} &nbsp;&middot;&nbsp; {len(matches)} item(s) on sale</p>
      </div>
      <table style="width:100%;border-collapse:collapse;background:white;border:1px solid #ddd;border-top:none;">
        <thead><tr style="background:#f8f8f8;font-size:11px;color:#888;text-transform:uppercase;">
          <th style="padding:8px;"></th>
          <th style="padding:8px;text-align:left;">Item</th>
          <th style="padding:8px;text-align:right;">Price</th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <div style="padding:16px;background:#f0f7f3;border:1px solid #ddd;border-top:none;border-radius:0 0 8px 8px;text-align:center;">
        <a href="https://www.publix.com/savings/weekly-ad/view-all"
           style="background:#1a6b3c;color:white;padding:10px 24px;border-radius:4px;text-decoration:none;font-weight:600;">
          View Full Weekly Ad &#x2197;
        </a>
      </div>
    </body></html>"""


def send_alert(notify_email: str, matches: list[dict], store_id: str, store_name: str):
    today = date.today().strftime("%B %d")
    resend.Emails.send({
        "from":    RESEND_FROM,
        "to":      [notify_email],
        "subject": f"\U0001f6d2 Publix Deals \u2014 {len(matches)} item(s) on sale ({today})",
        "html":    build_html(matches, store_id, store_name),
    })
    print(f"   Email sent \u2192 {notify_email}")


# ── Lambda handler ────────────────────────────────────────────────────────────

def handler(event, context):
    """Lambda entry point \u2014 called by EventBridge weekly."""
    main()
    return {"statusCode": 200, "body": "Done."}


def main():
    started_at = datetime.now(timezone.utc)
    print(f"\nPublix Deal Checker \u2014 {date.today()}")
    print("=" * 50)

    job = {
        "job_id":          started_at.strftime("%Y%m%d-%H%M%S"),
        "started_at":      started_at.isoformat(),
        "finished_at":     "",
        "stores_examined": 0,
        "total_deals":     0,
        "emails_sent":     0,
        "errors":          [],
        "store_details":   [],
    }

    users = get_all_users()
    print(f"Loaded {len(users)} registered user(s)")
    if not users:
        print("No users \u2014 nothing to do.")
        job["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_scrape_log(job)
        return

    by_store: dict[str, list] = {}
    for user in users:
        store_id = str((user.get("prefs") or {}).get("store_id") or "").strip()
        if not store_id:
            print(f"  Skipping {user['email']} \u2014 no store configured")
            continue
        by_store.setdefault(store_id, []).append(user)

    if not by_store:
        print("No users have a store configured.")
        job["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_scrape_log(job)
        return

    print(f"Stores to check: {list(by_store.keys())}\n")
    job["stores_examined"] = len(by_store)

    for store_id, store_users in by_store.items():
        prefs0     = store_users[0].get("prefs") or {}
        store_name = prefs0.get("store_name") or ""
        store_info = {"store_id": store_id, "store_name": store_name, "deals": 0, "emails": 0}
        print(f"\u25b6 {store_name or f'Store #{store_id}'}")

        try:
            deals = get_deals(store_id)
            print(f"  {len(deals)} deals fetched")
            store_info["deals"] = len(deals)
            job["total_deals"] += len(deals)
        except Exception as e:
            msg = f"ERROR fetching deals for store {store_id}: {e}"
            print(f"  {msg}")
            job["errors"].append(msg)
            continue

        try:
            cache_deals(store_id, deals)
            print(f"  Deals cached to DynamoDB")
        except Exception as e:
            job["errors"].append(f"WARNING: cache failed for {store_id}: {e}")

        for user in store_users:
            account_email = user["email"]
            prefs         = user.get("prefs") or {}
            notify_email  = (prefs.get("notify_email") or account_email).strip()
            items         = prefs.get("items") or []
            matching      = prefs.get("matching") or {}

            print(f"  Matching for {account_email} ({len(items)} items)\u2026")

            if not items:
                print(f"    No items on list \u2014 skipping email")
                continue

            matches = match_deals_for_user(deals, items, matching)

            if not matches:
                print(f"    No matches this week")
                continue

            print(f"    {len(matches)} match(es) \u2014 sending to {notify_email}")
            try:
                send_alert(notify_email, matches, store_id, store_name)
                job["emails_sent"] += 1
                store_info["emails"] += 1
            except Exception as e:
                msg = f"ERROR sending email to {notify_email}: {e}"
                print(f"    {msg}")
                job["errors"].append(msg)

        job["store_details"].append(store_info)

    job["finished_at"] = datetime.now(timezone.utc).isoformat()
    write_scrape_log(job)
    print("\nDone.")


if __name__ == "__main__":
    os.environ.setdefault("USERS_TABLE", "publix-deal-checker-users")
    os.environ.setdefault("DEALS_TABLE", "publix-deal-checker-deals")
    os.environ.setdefault("RESEND_API_KEY", "test")
    os.environ.setdefault("RESEND_FROM_NAME", "Publix Alerts")
    os.environ.setdefault("RESEND_FROM_ADDR", "onboarding@resend.dev")
    main()
