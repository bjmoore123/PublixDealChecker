"""shared/deal_parser.py — Unified deal parsing for both Lambdas.

Used by:
  - lambda/deals.py   (API Lambda)
  - scraper/scraper.py (Scraper Lambda)

Both Lambdas include the shared/ directory in their deployment packages.
"""
import re

# Comprehensive BOGO regex — covers b1g1, b2g1, "buy one get one", "buy 2 get 1", etc.
_BOGO_RE = re.compile(r"b[12]g1|buy\s+\d.{0,8}get\s+\d|buy\s+one.{0,10}get\s+one", re.IGNORECASE)


def parse_deal(d: dict) -> dict:
    """Parse and enrich a deal dict from either a raw Publix API response or a cached record.

    Accepts both camelCase (raw API) and snake_case (cached) field names.
    Returns a standardised dict with all computed boolean fields.
    """
    saving_type = d.get("saving_type") or d.get("savingType") or "WeeklyAd"
    brand_lower  = (d.get("brand") or "").lower()
    title_lower  = (d.get("title") or "").lower()
    savings_str  = (d.get("savings") or "").lower()
    categories   = d.get("categories") or []

    bogo_text = title_lower + " " + savings_str
    is_bogo   = "bogo" in categories or bool(_BOGO_RE.search(bogo_text))

    # Coupon ID — prefer dcId (raw) then coupon_id (cached)
    coupon_raw = d.get("dcId") or d.get("coupon_id")
    coupon_id  = str(coupon_raw) if coupon_raw else ""

    return {
        "id":              str(d.get("id", "")),
        "title":           d.get("title", ""),
        "description":     d.get("description", ""),
        "savings":         d.get("savings", ""),
        "save_line":       d.get("save_line") or d.get("additionalDealInfo", ""),
        "fine_print":      d.get("finePrint") or d.get("fine_print", ""),
        "brand":           d.get("brand", ""),
        "department":      d.get("department", ""),
        "valid_from":      d.get("valid_from") or d.get("wa_startDateFormatted", ""),
        "valid_thru":      d.get("valid_thru") or d.get("wa_endDateFormatted", ""),
        "image_url":       d.get("image_url") or d.get("enhancedImageUrl") or d.get("imageUrl", ""),
        "saving_type":     saving_type,
        "coupon_id":       coupon_id,
        "categories":      categories,
        "is_bogo":         is_bogo,
        "is_publix_brand": brand_lower == "publix" or title_lower.startswith("publix "),
        "has_coupon":      bool(d.get("has_coupon") or d.get("hasCoupon")) or saving_type in ("PrintableCoupon", "DigitalCoupon"),
        "is_stacked":      saving_type == "StackedDeals",
        "is_extra":        saving_type == "ExtraSavings",
    }
