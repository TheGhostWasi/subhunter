"""
Optional, bounded subdomain permutation generation.

Given discovered hosts like dev.example.com and api.example.com, generate
plausible combinations like dev-api.example.com. Deliberately bounded to
avoid a combinatorial explosion — this is a *seed* for DNS verification,
not a brute-force wordlist replacement.
"""

# A small, high-signal set of common infra prefixes/suffixes to combine with
# labels already discovered on the target — keeps the permutation space bounded.
COMMON_TOKENS = ["dev", "staging", "stage", "test", "qa", "uat", "prod", "api", "admin", "internal", "beta"]

MAX_LABELS_TO_COMBINE = 15   # cap how many discovered first-labels we use as seeds
MAX_PERMUTATIONS = 2000      # hard ceiling regardless of input size


def generate_permutations(hosts, root_domain, max_permutations=MAX_PERMUTATIONS):
    """
    hosts: iterable of already-discovered hostnames (full, e.g. "dev.example.com")
    Returns a bounded set of candidate hostnames (not yet DNS-verified).
    """
    root_domain = root_domain.lower()
    first_labels = set()

    for h in hosts:
        h = h.lower()
        if h == root_domain or not h.endswith("." + root_domain):
            continue
        label = h[: -(len(root_domain) + 1)].split(".")[0]
        if label and label not in COMMON_TOKENS:
            first_labels.add(label)
        first_labels.add(label)  # also allow combining discovered tokens with themselves

    seeds = list(first_labels)[:MAX_LABELS_TO_COMBINE]
    tokens = COMMON_TOKENS

    candidates = set()
    for seed in seeds:
        for token in tokens:
            if token == seed:
                continue
            candidates.add(f"{token}-{seed}.{root_domain}")
            candidates.add(f"{seed}-{token}.{root_domain}")
            if len(candidates) >= max_permutations:
                return candidates

    return candidates
