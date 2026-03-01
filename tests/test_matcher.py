"""tests/test_matcher.py — Tests for fuzzy matching logic.

Tests the precision+coverage hybrid scorer in scraper/matcher.py.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scraper"))

from matcher import match_deals_for_user


def _deal(title, id_="1", savings="$2", department="Grocery"):
    return {"id": id_, "title": title, "savings": savings,
            "description": "", "brand": "", "department": department,
            "save_line": "", "fine_print": "", "valid_from": "", "valid_thru": ""}


class TestMatchDeals:
    def test_exact_title_match(self):
        deals   = [_deal("Publix Whole Milk Gallon")]
        matches = match_deals_for_user(deals, ["whole milk"], {"threshold": 70})
        assert len(matches) == 1
        assert matches[0]["my_item"] == "whole milk"

    def test_no_match_below_threshold(self):
        deals   = [_deal("Organic Kale Chips")]
        matches = match_deals_for_user(deals, ["chocolate cake"], {"threshold": 80})
        assert len(matches) == 0

    def test_empty_items_list(self):
        deals   = [_deal("Publix Whole Milk")]
        matches = match_deals_for_user(deals, [], {"threshold": 70})
        assert len(matches) == 0

    def test_empty_deals_list(self):
        matches = match_deals_for_user([], ["milk"], {"threshold": 70})
        assert len(matches) == 0

    def test_deduplication_same_deal_two_items(self):
        """Same deal id should appear at most once even if two items match it."""
        deals   = [_deal("Publix Whole Milk Gallon", id_="42")]
        items   = ["whole milk", "milk gallon"]
        matches = match_deals_for_user(deals, items, {"threshold": 60})
        assert len(matches) == 1

    def test_multiple_deals_multiple_items(self):
        deals = [_deal("Publix Whole Milk", id_="1"), _deal("Chicken Breast", id_="2")]
        items = ["milk", "chicken"]
        matches = match_deals_for_user(deals, items, {"threshold": 60})
        assert len(matches) == 2

    def test_missing_threshold_defaults_gracefully(self):
        """Should not crash when threshold key is absent."""
        deals   = [_deal("Publix Milk")]
        matches = match_deals_for_user(deals, ["milk"], {})
        # With default threshold 75 a simple "milk" match should score high enough
        assert isinstance(matches, list)

    def test_dict_item_with_name_key(self):
        """Items can be stored as dicts with a 'name' key."""
        deals   = [_deal("Publix Orange Juice")]
        matches = match_deals_for_user(deals, [{"name": "orange juice", "mode": "fuzzy"}], {"threshold": 70})
        assert len(matches) == 1
        assert matches[0]["my_item"] == "orange juice"

    def test_plain_string_item(self):
        """Legacy plain-string items are also supported."""
        deals   = [_deal("Publix Butter Unsalted")]
        matches = match_deals_for_user(deals, ["butter"], {"threshold": 65})
        assert len(matches) == 1
