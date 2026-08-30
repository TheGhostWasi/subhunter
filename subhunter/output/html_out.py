"""Self-contained HTML report — no external frontend framework, no CDN dependency."""

import html
import datetime

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SubHunter Report — {target}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f1117; color:#e6e6e6; margin:0; padding:2rem; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.2rem; }}
  .meta {{ color:#9aa4b2; margin-bottom: 1.5rem; font-size: 0.9rem; }}
  .stats {{ display:flex; gap:1rem; margin-bottom:1.5rem; flex-wrap:wrap; }}
  .stat {{ background:#171a23; border:1px solid #262b38; border-radius:8px; padding:0.8rem 1.2rem; min-width:120px; }}
  .stat .num {{ font-size:1.4rem; font-weight:600; }}
  .stat .label {{ color:#9aa4b2; font-size:0.8rem; }}
  table {{ width:100%; border-collapse: collapse; font-size:0.85rem; }}
  th, td {{ text-align:left; padding:0.5rem 0.7rem; border-bottom:1px solid #262b38; vertical-align:top; }}
  th {{ color:#9aa4b2; font-weight:600; position:sticky; top:0; background:#0f1117; }}
  tr:hover {{ background:#171a23; }}
  .badge {{ display:inline-block; padding:0.1rem 0.5rem; border-radius:4px; font-size:0.75rem; margin-right:0.2rem;}}
  .badge-scope {{ background:#1c3a2e; color:#5fd68a; }}
  .badge-outscope {{ background:#3a301c; color:#e0b95f; }}
  .badge-excluded {{ background:#3a1c1c; color:#e05f5f; }}
  .badge-http {{ background:#1c2c3a; color:#5fb8e0; }}
  code {{ color:#9aa4b2; font-size:0.8rem; }}
</style>
</head>
<body>
  <h1>SubHunter Report — {target}</h1>
  <div class="meta">Scanned {scan_time} &middot; Duration {duration:.1f}s</div>

  <div class="stats">
    <div class="stat"><div class="num">{candidates}</div><div class="label">Candidates</div></div>
    <div class="stat"><div class="num">{dns_resolved}</div><div class="label">DNS Resolved</div></div>
    <div class="stat"><div class="num">{http_live}</div><div class="label">HTTP Live</div></div>
    <div class="stat"><div class="num">{https_live}</div><div class="label">HTTPS Live</div></div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Host</th><th>Sources</th><th>A / AAAA</th><th>CNAME</th>
        <th>HTTP</th><th>Title</th><th>Server</th><th>Tech</th><th>Scope</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</body>
</html>
"""

_ROW_TEMPLATE = """<tr>
  <td>{host}</td>
  <td><code>{sources}</code></td>
  <td>{ips}</td>
  <td>{cname}</td>
  <td>{http_status}</td>
  <td>{title}</td>
  <td>{server}</td>
  <td>{tech}</td>
  <td>{scope_badges}</td>
</tr>"""


def _e(s):
    return html.escape(str(s)) if s is not None else ""


def build_html(result):
    rows = []
    for h in sorted(result.hosts.values(), key=lambda x: x.host):
        ips = ", ".join((h.dns.a + h.dns.aaaa)) if h.dns else ""
        cname = h.dns.cname if h.dns else ""
        http_status = f"{h.http.scheme.upper()} {h.http.status}" if (h.http and h.http.status) else ""
        title = h.http.title if h.http else ""
        server = h.http.server if h.http else ""
        tech = ", ".join(h.http.technologies) if h.http else ""

        badges = []
        if h.excluded:
            badges.append('<span class="badge badge-excluded">excluded</span>')
        elif not h.in_scope:
            badges.append('<span class="badge badge-outscope">out of scope</span>')
        else:
            badges.append('<span class="badge badge-scope">in scope</span>')
        if h.http and h.http.status:
            badges.append('<span class="badge badge-http">http</span>')

        rows.append(_ROW_TEMPLATE.format(
            host=_e(h.host), sources=_e(", ".join(sorted(h.sources))),
            ips=_e(ips), cname=_e(cname), http_status=_e(http_status),
            title=_e(title), server=_e(server), tech=_e(tech),
            scope_badges="".join(badges),
        ))

    s = result.summary()
    return _TEMPLATE.format(
        target=_e(result.target),
        scan_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        duration=result.duration_seconds,
        candidates=s["candidates"], dns_resolved=s["dns_resolved"],
        http_live=s["http_live"], https_live=s["https_live"],
        rows="\n      ".join(rows),
    )


def write_html(result, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_html(result))
