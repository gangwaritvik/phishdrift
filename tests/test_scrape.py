def test_clean_brand_strips_accents():
    from features.scrape import _clean_brand

    assert _clean_brand("Hermès") == "hermes"


def test_brand_files_added_and_exclusions_win(tmp_path):
    from features.scrape import apply_brand_files, read_brand_file

    f = tmp_path / "add.txt"
    f.write_text("# header\nRevolut  # fintech\nswiggy\nabc\n\nhome\n", encoding="utf-8")
    assert read_brand_file(f) == ["revolut", "swiggy", "home"]  # "abc" is under 4 letters
    out = apply_brand_files({"paypal", "group"}, [f], ["home", "group"])
    assert out == {"paypal", "revolut", "swiggy"}
