import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from subhunter.core.permutations import generate_permutations, MAX_PERMUTATIONS


def test_generates_bounded_set():
    hosts = ["dev.example.com", "api.example.com", "staging.example.com"]
    result = generate_permutations(hosts, "example.com")
    assert len(result) <= MAX_PERMUTATIONS
    assert all(h.endswith("example.com") for h in result)


def test_empty_hosts_gives_empty_permutations():
    result = generate_permutations([], "example.com")
    assert result == set()


def test_ignores_hosts_outside_domain():
    hosts = ["dev.other-domain.com"]
    result = generate_permutations(hosts, "example.com")
    assert result == set()
