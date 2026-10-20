from experiments.brand_evidence import evidence


def test_counts_domains_and_shows_longer_words():
    phishing = [
        "https://revolut-login.example.com/x",
        "https://a.example.com/revolution",
        "http://other.net/revolut",
        "badurl",
    ]
    benign = ["https://www.revolut.com/app", "https://news.org/the-revolution"]
    t = evidence(["revolut"], phishing, benign).set_index("name").loc["revolut"]
    assert t.phishing_domains == 2  # example.com and other.net
    assert "revolution:1" in t.top_words
    assert t.benign_domains == 1  # the brand's own revolut.com is left out
