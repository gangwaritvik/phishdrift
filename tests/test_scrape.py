def test_clean_brand_strips_accents():
    from features.scrape import _clean_brand

    assert _clean_brand("Hermès") == "hermes"
