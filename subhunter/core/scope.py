"""
Scope control for authorized reconnaissance.

A scope file lists what's authorized to test (e.g. "*.example.com").
An exclude file lists what must never be actively probed even if in scope.
Out-of-scope / excluded hosts are still reported as *discovered* but are
never actively probed (HTTP, permutation-DNS follow-ups, etc).
"""

import fnmatch
from pathlib import Path
from typing import List, Optional


def _load_patterns(path: str) -> List[str]:
    patterns = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    return patterns


class Scope:
    """Holds optional scope/exclude pattern lists and answers matching queries."""

    def __init__(self, scope_file: Optional[str] = None, exclude_file: Optional[str] = None):
        self.scope_patterns = _load_patterns(scope_file) if scope_file else []
        self.exclude_patterns = _load_patterns(exclude_file) if exclude_file else []

    @property
    def has_scope(self) -> bool:
        return bool(self.scope_patterns)

    @staticmethod
    def _matches_any(host: str, patterns: List[str]) -> bool:
        host = host.lower()
        for pattern in patterns:
            if fnmatch.fnmatch(host, pattern):
                return True
        return False

    def is_in_scope(self, host: str) -> bool:
        """If no scope file was given, everything is considered in scope."""
        if not self.has_scope:
            return True
        return self._matches_any(host, self.scope_patterns)

    def is_excluded(self, host: str) -> bool:
        if not self.exclude_patterns:
            return False
        return self._matches_any(host, self.exclude_patterns)

    def evaluate(self, host: str):
        """Returns (in_scope: bool, excluded: bool) for a host."""
        excluded = self.is_excluded(host)
        in_scope = self.is_in_scope(host) and not excluded
        return in_scope, excluded
