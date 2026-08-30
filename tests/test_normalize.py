import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from subhunter.core.normalize import normalize_hostname, is_subdomain_of


def test_lowercases():
    assert normalize_hostname("API.Example.COM") == "api.example.com"


def test_strips_trailing_dot():
    assert normalize_hostname("api.example.com.") == "api.example.com"


def test_strips_protocol():
    assert normalize_hostname("https://api.example.com") == "api.example.com"


def test_strips_path():
    assert normalize_hostname("https://api.example.com/v1/users?x=1") == "api.example.com"


def test_strips_port():
    assert normalize_hostname("api.example.com:8080") == "api.example.com"


def test_strips_userinfo():
    assert normalize_hostname("user:pass@api.example.com") == "api.example.com"


def test_strips_wildcard_prefix():
    assert normalize_hostname("*.example.com") == "example.com"


def test_strips_whitespace():
    assert normalize_hostname("  api.example.com  ") == "api.example.com"


def test_rejects_single_label():
    assert normalize_hostname("localhost") is None


def test_rejects_empty():
    assert normalize_hostname("") is None
    assert normalize_hostname(None) is None


def test_rejects_malformed():
    assert normalize_hostname("---.example.com") is None
    assert normalize_hostname("api..example.com") is None


def test_rejects_too_long():
    long_label = "a" * 300
    assert normalize_hostname(f"{long_label}.example.com") is None


def test_is_subdomain_of():
    assert is_subdomain_of("api.example.com", "example.com") is True
    assert is_subdomain_of("example.com", "example.com") is True
    assert is_subdomain_of("dev.api.example.com", "example.com") is True
    assert is_subdomain_of("api.evil-example.com", "example.com") is False
    assert is_subdomain_of("notexample.com", "example.com") is False
