import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from subhunter.core.resolver import filter_wildcard_false_positives


def test_no_wildcard_ips_no_filtering():
    results = {"a.example.com": {"a": ["1.2.3.4"], "aaaa": [], "cname": None}}
    filtered, removed = filter_wildcard_false_positives(results, set())
    assert removed == 0
    assert filtered == results


def test_removes_hosts_matching_wildcard_ip():
    wildcard_ips = {"1.2.3.4"}
    results = {
        "real.example.com": {"a": ["5.6.7.8"], "aaaa": [], "cname": None},
        "fake1.example.com": {"a": ["1.2.3.4"], "aaaa": [], "cname": None},
        "fake2.example.com": {"a": ["1.2.3.4"], "aaaa": [], "cname": None},
    }
    filtered, removed = filter_wildcard_false_positives(results, wildcard_ips)
    assert removed == 2
    assert "real.example.com" in filtered
    assert "fake1.example.com" not in filtered


def test_keeps_wildcard_ip_host_if_it_has_distinguishing_cname():
    wildcard_ips = {"1.2.3.4"}
    results = {
        "cdn.example.com": {"a": ["1.2.3.4"], "aaaa": [], "cname": "cdn-provider.net"},
    }
    filtered, removed = filter_wildcard_false_positives(results, wildcard_ips)
    assert removed == 0
    assert "cdn.example.com" in filtered
