"""Clean, professional terminal output (Phase 14 & 15)."""

import sys

_USE_COLOR = sys.stdout.isatty()


def _c(text, code):
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def green(t): return _c(t, "92")
def cyan(t): return _c(t, "96")
def yellow(t): return _c(t, "93")
def red(t): return _c(t, "91")
def dim(t): return _c(t, "2")
def bold(t): return _c(t, "1")


def render_summary_box(result, title="SUBHUNTER v2.0"):
    s = result.summary()
    lines = [
        f"Target       : {result.target}",
        f"Candidates   : {s['candidates']:,}",
        f"DNS Resolved : {s['dns_resolved']:,}",
    ]
    if any(h.http for h in result.hosts.values()):
        lines.append(f"HTTP Live    : {s['http_live']:,}")
        lines.append(f"HTTPS Live   : {s['https_live']:,}")
    if result.wildcard_detected:
        lines.append(f"Wildcard DNS : detected ({result.wildcard_removed} filtered)")
    lines.append(f"Duration     : {result.duration_seconds:.1f}s")

    width = max(len(title), max(len(l) for l in lines)) + 4
    top = "╭" + "─" * width + "╮"
    sep = "├" + "─" * width + "┤"
    bot = "╰" + "─" * width + "╯"

    out = [top, f"│ {title.center(width - 2)} │", sep]
    for l in lines:
        out.append(f"│ {l.ljust(width - 2)} │")
    out.append(bot)
    return "\n".join(out)


def render_host_line(host_obj, show_sources=False, show_dns=False, show_http=False):
    parts = [green(host_obj.host)]

    if show_dns and host_obj.dns:
        ips = host_obj.dns.a + host_obj.dns.aaaa
        if ips:
            parts.append(dim(f"-> {', '.join(ips)}"))
        if host_obj.dns.cname:
            parts.append(dim(f"(CNAME: {host_obj.dns.cname})"))

    if not host_obj.in_scope:
        parts.append(yellow("[out-of-scope]"))
    if host_obj.excluded:
        parts.append(red("[excluded]"))

    if show_http and host_obj.http and host_obj.http.status is not None:
        parts.append(cyan(f"[{host_obj.http.scheme.upper()} {host_obj.http.status}]"))
        if host_obj.http.title:
            parts.append(dim(f'"{host_obj.http.title}"'))
        if host_obj.http.server:
            parts.append(dim(f"Server:{host_obj.http.server}"))
        if host_obj.http.technologies:
            parts.append(dim(f"Tech:{','.join(host_obj.http.technologies)}"))
        if host_obj.http.cdn_waf:
            parts.append(yellow(",".join(host_obj.http.cdn_waf)))

    line = "  " + " ".join(parts)
    if show_sources and host_obj.sources:
        line += "\n      " + dim(f"Sources: {', '.join(sorted(host_obj.sources))}")
    return line
