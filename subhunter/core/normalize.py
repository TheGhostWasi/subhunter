"""
Robust hostname normalization and validation.

Passive sources return messy data: mixed case, trailing dots, accidental
protocols/paths (especially from Wayback Machine URLs), whitespace, and
outright garbage. Every hostname must pass through here before it's trusted.
"""

import re
from typing import Optional

# RFC-1035-ish hostname validation: labels of letters/digits/hyphens,
# no leading/trailing hyphen per label, overall length sane.
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_MAX_HOSTNAME_LEN = 253


def normalize_hostname(raw: str) -> Optional[str]:
    """
    Clean and validate a single raw hostname string.
    Returns the normalized hostname, or None if it's malformed/unusable.
    """
    if not raw:
        return None

    host = raw.strip().lower()

    # Strip accidental protocol (Wayback/CommonCrawl URLs commonly leak these in)
    host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", host)

    # Strip path/query/fragment if a full URL slipped through
    host = host.split("/")[0].split("?")[0].split("#")[0]

    # Strip userinfo (user:pass@host) and port
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    host = host.split(":")[0]

    # Strip trailing dot (FQDN notation) and stray whitespace/control chars
    host = host.rstrip(".").strip()

    # Strip a leading wildcard label like "*.example.com" -> "example.com"
    if host.startswith("*."):
        host = host[2:]

    if not host or len(host) > _MAX_HOSTNAME_LEN:
        return None

    labels = host.split(".")
    if len(labels) < 2:
        return None  # not a real domain (single label)

    for label in labels:
        if not _LABEL_RE.match(label):
            return None

    return host


def is_subdomain_of(host: str, root_domain: str) -> bool:
    """True if host == root_domain or host is a (nested) subdomain of it."""
    host = host.lower().rstrip(".")
    root_domain = root_domain.lower().rstrip(".")
    return host == root_domain or host.endswith("." + root_domain)
