"""
scraper/matcher.py  (v3)

Match deals against a user's personal item list using fuzzy matching.
Works with v4/savings API deal shape.
"""

from rapidfuzz import fuzz


def match_deals_for_user(
    deals:        list[dict],
    items:        list[str],
    matching_cfg: dict,
) -> list[dict]:
    threshold = int(matching_cfg.get("threshold", 75))

    matches = []
    seen    = set()

    for deal in deals:
        title = deal.get("title", "")
        if not title:
            continue

        for item in items:
            score = fuzz.token_set_ratio(item.lower(), title.lower())
            if score >= threshold:
                key = deal.get("id") or title
                if key not in seen:
                    seen.add(key)
                    matches.append({
                        "my_item":     item,
                        "deal_name":   title,
                        "description": deal.get("description", ""),
                        "brand":       deal.get("brand", ""),
                        "department":  deal.get("department", ""),
                        "savings":     deal.get("savings", ""),
                        "save_line":   deal.get("save_line", ""),
                        "fine_print":  deal.get("fine_print", ""),
                        "valid_from":  deal.get("valid_from", ""),
                        "valid_thru":  deal.get("valid_thru", ""),
                        "image_url":   deal.get("image_url", ""),
                        "match_score": score,
                    })

    matches.sort(key=lambda x: x["match_score"], reverse=True)
    return matches
