"""Structured JSON output (Phase 16)."""

import json
import datetime


def build_json(result):
    return {
        "target": result.target,
        "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "duration_seconds": round(result.duration_seconds, 2),
        "summary": result.summary(),
        "wildcard": {
            "detected": result.wildcard_detected,
            "ips": sorted(result.wildcard_ips),
            "false_positives_removed": result.wildcard_removed,
        },
        "sources": result.source_counts,
        "hosts": [h.to_dict() for h in sorted(result.hosts.values(), key=lambda x: x.host)],
    }


def write_json(result, path):
    with open(path, "w") as f:
        json.dump(build_json(result), f, indent=2, default=str)
