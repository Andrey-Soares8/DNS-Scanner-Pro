from scanner_core import clean_wordlist, is_valid_domain, normalize_domain


def test_normalize_domain_from_url():
    assert normalize_domain("https://example.com/login") == "example.com"


def test_domain_validation():
    assert is_valid_domain("example.com")
    assert not is_valid_domain("https://example.com")
    assert not is_valid_domain("bad domain.com")


def test_clean_wordlist_removes_duplicates_comments_and_invalid_entries():
    lines = ["www", "www", "# comment", "admin # inline", "bad entry", "api"]
    assert clean_wordlist(lines) == ["www", "admin", "api"]
