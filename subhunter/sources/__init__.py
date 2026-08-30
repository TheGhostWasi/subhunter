"""
Passive source plugin registry.

Each source module exposes:
  NAME: str
  REQUIRES_API_KEY: bool
  API_KEY_ENV: str (only if REQUIRES_API_KEY)
  async def fetch(session, domain) -> set[str]   (raw, unnormalized hostnames)

Adding a new source = drop a new module here + register it below.
No source failure can take down the whole scan.
"""

import asyncio
import os

from . import crtsh, hackertarget, otx, threatminer, wayback, anubis
from . import certspotter, urlscan, rapiddns, commoncrawl, securitytrails

ALL_SOURCE_MODULES = [
    crtsh, hackertarget, otx, threatminer, wayback, anubis,
    certspotter, urlscan, rapiddns, commoncrawl, securitytrails,
]

SOURCES_BY_NAME = {m.NAME: m for m in ALL_SOURCE_MODULES}


def available_sources(include_key_gated=True):
    """
    Returns the list of source names that will actually run:
    key-gated sources are excluded unless their env var is set
    (or include_key_gated=False forces them all to be listed as attempted).
    """
    names = []
    for m in ALL_SOURCE_MODULES:
        if getattr(m, "REQUIRES_API_KEY", False):
            if include_key_gated and not os.environ.get(getattr(m, "API_KEY_ENV", ""), ""):
                continue
        names.append(m.NAME)
    return names


async def _run_one(module, session, domain, timeout_s=30):
    """Run a single source with a hard timeout; never raises."""
    try:
        return await asyncio.wait_for(module.fetch(session, domain), timeout=timeout_s)
    except Exception:
        return set()


async def run_all_sources(session, domain, selected=None, progress_cb=None):
    """
    Run all (or selected) passive sources concurrently.
    progress_cb(source_name, count_or_None) is called as each source finishes;
    count is None when the source was unavailable/skipped.
    Returns dict {hostname_raw: set(source_names)} — raw hostnames need normalize.normalize_hostname().
    """
    modules = [SOURCES_BY_NAME[n] for n in (selected or SOURCES_BY_NAME.keys()) if n in SOURCES_BY_NAME]

    tasks = {}
    for m in modules:
        if getattr(m, "REQUIRES_API_KEY", False) and not os.environ.get(getattr(m, "API_KEY_ENV", ""), ""):
            if progress_cb:
                progress_cb(m.NAME, None)  # unavailable — no key configured
            continue
        tasks[m.NAME] = asyncio.create_task(_run_one(m, session, domain))

    host_sources = {}
    for name, task in tasks.items():
        result = await task
        for host in result:
            host_sources.setdefault(host, set()).add(name)
        if progress_cb:
            progress_cb(name, len(result))

    return host_sources
