import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from subhunter.cli import build_parser


def test_requires_domain():
    parser = build_parser()
    try:
        parser.parse_args([])
        assert False, "should have raised SystemExit"
    except SystemExit:
        pass


def test_basic_domain_parses():
    parser = build_parser()
    args = parser.parse_args(["-d", "example.com"])
    assert args.domain == "example.com"
    assert args.active is False
    assert args.http is False


def test_v1_flags_still_work():
    parser = build_parser()
    args = parser.parse_args([
        "-d", "example.com", "-a", "-w", "words.txt",
        "-o", "out.txt", "--json", "-r", "1.1.1.1,8.8.8.8",
        "-c", "500", "-s",
    ])
    assert args.active is True
    assert args.wordlist == "words.txt"
    assert args.output == "out.txt"
    assert args.json is True
    assert args.resolvers == "1.1.1.1,8.8.8.8"
    assert args.concurrency == 500
    assert args.silent is True


def test_v2_flags_parse():
    parser = build_parser()
    args = parser.parse_args([
        "-d", "example.com", "--http", "--ip-info", "--permutations",
        "--csv", "--html", "report.html", "--dns-timeout", "5",
        "--dns-retries", "2", "--extra-dns", "--show-sources", "--debug",
    ])
    assert args.http is True
    assert args.ip_info is True
    assert args.permutations is True
    assert args.csv is True
    assert args.html == "report.html"
    assert args.dns_timeout == 5.0
    assert args.dns_retries == 2
    assert args.extra_dns is True
    assert args.show_sources is True
    assert args.debug is True
