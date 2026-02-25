"""
scraper/scraper.py  (v3 - serverless)

Fetches all current Weekly Ad deals for a Publix store via the
services.publix.com/api/v4/savings REST endpoint.
Plain urllib — no browser, no Playwright needed.
"""

import json
import urllib.request

SAVINGS_URL = (
    "https://services.publix.com/api/v4/savings"
    "?smImg=235&enImg=368&fallbackImg=false&isMobile=false"
    "&page=1&pageSize=0&includePersonalizedDeals=false"
    "&languageID=1&isWeb=true&getSavingType=AllDeals"
)


def get_deals(store_id: str) -> list[dict]:
    req = urllib.request.Request(
        SAVINGS_URL,
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
        raw = json.loads(resp.read().decode())

    items = raw.get("Savings") or []
    deals = []
    for d in items:
        deals.append({
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
            "saving_type": d.get("savingType", ""),
            "on_sale":     True,
        })
    return deals
