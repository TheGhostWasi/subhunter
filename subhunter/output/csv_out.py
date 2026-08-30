"""CSV output for spreadsheet analysis (Phase 16)."""

import csv


FIELDNAMES = [
    "host", "sources", "a", "aaaa", "cname",
    "http_status", "http_title", "http_server", "technologies",
    "in_scope", "excluded",
]


def write_csv(result, path):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for h in sorted(result.hosts.values(), key=lambda x: x.host):
            row = {
                "host": h.host,
                "sources": ";".join(sorted(h.sources)),
                "a": ";".join(h.dns.a) if h.dns else "",
                "aaaa": ";".join(h.dns.aaaa) if h.dns else "",
                "cname": h.dns.cname if h.dns else "",
                "http_status": h.http.status if h.http else "",
                "http_title": h.http.title if h.http else "",
                "http_server": h.http.server if h.http else "",
                "technologies": ";".join(h.http.technologies) if h.http else "",
                "in_scope": h.in_scope,
                "excluded": h.excluded,
            }
            writer.writerow(row)
