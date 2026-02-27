"""
scraper/scraper.py  (v5 - serverless)

Fetches all current deals for a Publix store via the
services.publix.com/api/v4/savings REST endpoint.

KEY: `publixstore` must be sent as a REQUEST HEADER, not a query param.
     - WeeklyAd deals (BOGOs, regular sales) require getSavingType=WeeklyAd
     - Digital coupons require getSavingType=AllDeals  
     Both are fetched and merged.
"""

import json
import urllib.request

_BASE_URL = (
    "https://services.publix.com/api/v4/savings"
    "?smImg=235&enImg=368&fallbackImg=false&isMobile=false"
    "&page=1&pageSize=0&includePersonalizedDeals=false"
    "&languageID=1&isWeb=true"
)

SAVINGS_URL_WEEKLY = _BASE_URL + "&getSavingType=WeeklyAd"
SAVINGS_URL_COUPONS = _BASE_URL + "&getSavingType=AllDeals"


def _fetch(url: str, store_id: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "Accept":      "application/json, text/plain, */*",
            "Origin":      "https://www.publix.com",
            "Referer":     "https://www.publix.com/",
            "publixstore": str(store_id),
            "User-Agent":  (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/145.0.0.0 Safari/537.36"
            ),
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def _parse_item(d: dict) -> dict:
    saving_type = d.get("savingType", "")
    categories  = d.get("categories") or []
    title_lower = (d.get("title") or "").lower()
    savings_str = (d.get("savings") or "").lower()
    is_bogo = (
        "bogo" in categories
        or "buy 1 get 1" in savings_str
        or "buy one" in savings_str and "get one" in savings_str
        or "b1g1" in savings_str
        or "b1g1" in title_lower
    )
    return {
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
        "categories":  categories,
        "is_bogo":     is_bogo,
        "coupon_id":   str(d.get("dcId")) if d.get("dcId") else "",
        "on_sale":     True,
    }


def get_deals(store_id: str) -> list[dict]:
    """Fetch and merge Weekly Ad + Digital Coupon deals for a store."""
    seen_ids = set()
    deals = []

    # 1. Weekly Ad (BOGOs, regular sales, extra savings) — requires header-based store ID
    try:
        raw_wa = _fetch(SAVINGS_URL_WEEKLY, store_id)
        for d in (raw_wa.get("Savings") or []):
            item = _parse_item(d)
            if item["id"] and item["id"] not in seen_ids:
                seen_ids.add(item["id"])
                deals.append(item)
    except Exception as e:
        print(f"  Warning: Weekly Ad fetch failed for store {store_id}: {e}")

    # 2. Digital Coupons (separate pool — also requires header)
    try:
        raw_dc = _fetch(SAVINGS_URL_COUPONS, store_id)
        for d in (raw_dc.get("Savings") or []):
            item = _parse_item(d)
            if item["id"] and item["id"] not in seen_ids:
                seen_ids.add(item["id"])
                deals.append(item)
    except Exception as e:
        print(f"  Warning: Digital Coupon fetch failed for store {store_id}: {e}")

    return deals
