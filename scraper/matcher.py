"""
scraper/matcher.py  (v6.1)

Match deals against a user's personal item list using a precision+coverage
hybrid score that replaced token_set_ratio in v6.1.

The old token_set_ratio scored "publix chicken breast" at 100 against any deal
that contained all three words — including 14-word bundle titles like
"Any 2 Knorr Pasta ... AND Any 1 Publix Boneless Skinless Chicken Breast".
This made the sensitivity slider meaningless at the high end.

The new algorithm combines:
  precision = item_words_found / total_item_words  (did we find what we want?)
  coverage  = item_words_found / total_title_words (is the title about this?)

Weights vary by per-item mode:
  fuzzy → precision 70% + coverage 30%  (good for short terms like "chicken")
  exact → precision 40% + coverage 60%  (penalises long bundle titles heavily)

Items are stored as either plain strings (legacy) or dicts {name, mode}.
Both shapes are handled transparently.
"""


def _item_name(item) -> str:
    return item if isinstance(item, str) else (item.get("name") or "")


def _item_mode(item) -> str:
    return "fuzzy" if isinstance(item, str) else (item.get("mode") or "fuzzy")


def _match_score(item_str: str, title: str, mode: str) -> int:
    """Return 0–100 match score for item_str against deal title."""
    if not item_str or not title:
        return 0

    i_tokens = item_str.lower().split()
    t_tokens = title.lower().split()
    if not i_tokens or not t_tokens:
        return 0

    # Exact string match
    if item_str.lower() == title.lower():
        return 100

    matched = sum(
        1 for iw in i_tokens
        if any(iw in tw or tw in iw for tw in t_tokens)
    )

    precision = matched / len(i_tokens)
    coverage  = matched / len(t_tokens)

    # fuzzy: precision-heavy (65/35) — short terms like "chicken" score well
    # exact: balanced (50/50)  — penalises long bundle titles; threshold drops to 70
    p_weight = 0.5 if mode == "exact" else 0.65
    c_weight = 0.5 if mode == "exact" else 0.35

    return round((precision * p_weight + coverage * c_weight) * 100)


def match_deals_for_user(
    deals:        list[dict],
    items:        list,
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
            name  = _item_name(item)
            mode  = _item_mode(item)
            score = _match_score(name, title, mode)
            # exact-mode items use threshold 70; fuzzy-mode items use the user's slider value
            effective_threshold = min(threshold, 70) if mode == "exact" else threshold

            if score >= effective_threshold:
                key = deal.get("id") or title
                if key not in seen:
                    seen.add(key)
                    matches.append({
                        "my_item":     name,
                        "my_item_mode": mode,
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

