import sys, os, tempfile, json, csv
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from subhunter.core.models import Host, DNSInfo
from subhunter.core.enumerator import ScanResult
from subhunter.output import json_out, csv_out


def _sample_result():
    result = ScanResult()
    result.target = "example.com"
    result.duration_seconds = 1.23
    host = Host(host="api.example.com", sources={"crt.sh", "wayback"})
    host.dns = DNSInfo(a=["1.2.3.4"], aaaa=[], cname=None)
    result.hosts = {"api.example.com": host}
    result.source_counts = {"crt.sh": 5, "wayback": 3}
    return result


def test_json_structure():
    result = _sample_result()
    data = json_out.build_json(result)
    assert data["target"] == "example.com"
    assert data["summary"]["candidates"] == 0  # not set explicitly in this fixture
    assert data["hosts"][0]["host"] == "api.example.com"
    assert set(data["hosts"][0]["sources"]) == {"crt.sh", "wayback"}


def test_json_file_write_is_valid_json():
    result = _sample_result()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    json_out.write_json(result, path)
    with open(path) as f:
        data = json.load(f)
    assert data["target"] == "example.com"


def test_csv_file_write_is_valid_csv():
    result = _sample_result()
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        path = f.name
    csv_out.write_csv(result, path)
    with open(path) as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["host"] == "api.example.com"
    assert "crt.sh" in rows[0]["sources"]
