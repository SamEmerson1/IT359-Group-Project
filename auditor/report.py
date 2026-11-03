"""
report.py — render the findings, score, and AI explanations into a single
self-contained HTML report (no external files, opens in any browser).
"""

import html
from datetime import datetime
from auditor.core import Finding
from auditor.scoring import score, grade

_SEV_COLOR = {
    "CRITICAL": "#b00020", "HIGH": "#d35400", "MEDIUM": "#b7950b",
    "LOW": "#2471a3", "INFO": "#1e8449",
}


def _card(f: Finding) -> str:
    sev = f.severity.name
    status = "PASS" if f.passed else sev
    color = "#1e8449" if f.passed else _SEV_COLOR.get(sev, "#555")
    return f"""
    <div class="card" style="border-left:6px solid {color}">
      <div class="head">
        <span class="cat">{html.escape(f.category)}</span>
        <span class="badge" style="background:{color}">{status}</span>
      </div>
      <p class="test"><strong>Test:</strong> {html.escape(f.test_performed)}</p>
      <p><strong>Finding:</strong> {html.escape(f.finding)}</p>
      {f'<pre class="evi">{html.escape(f.evidence)}</pre>' if f.evidence else ''}
      <p class="exp"><strong>Explanation &amp; fix:</strong> {html.escape(f.ai_explanation or f.recommendation)}</p>
    </div>"""


def render_html(findings: list[Finding]) -> str:
    pts = score(findings)
    g = grade(pts)
    banner = {"Strong": "#1e8449", "Fair": "#b7950b",
              "Weak": "#d35400", "Critical": "#b00020"}.get(g, "#555")
    failed = sum(1 for f in findings if not f.passed)
    cards = "".join(_card(f) for f in findings)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authentication Security Report</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 860px; margin: 2rem auto;
          padding: 0 1rem; color: #222; line-height: 1.45; }}
  .score {{ background:{banner}; color:#fff; padding:1.2rem 1.5rem; border-radius:10px; }}
  .score h1 {{ margin:0; font-size:2.2rem; }}
  .score p {{ margin:.3rem 0 0; opacity:.95; }}
  .card {{ background:#fafafa; border:1px solid #e2e2e2; border-radius:8px;
           padding:1rem 1.2rem; margin:1rem 0; }}
  .head {{ display:flex; justify-content:space-between; align-items:center; }}
  .cat {{ font-size:1.15rem; font-weight:600; }}
  .badge {{ color:#fff; font-size:.75rem; font-weight:700; padding:.2rem .6rem;
            border-radius:999px; letter-spacing:.03em; }}
  .evi {{ background:#f0f0f0; padding:.6rem .8rem; border-radius:6px;
          overflow-x:auto; font-size:.85rem; white-space:pre-wrap; }}
  .test {{ color:#555; font-size:.92rem; }}
  .exp {{ background:#eef6ff; padding:.6rem .8rem; border-radius:6px; }}
  footer {{ color:#888; font-size:.8rem; margin-top:2rem; }}
</style></head><body>
  <div class="score">
    <h1>{pts}/100 &mdash; {g}</h1>
    <p>Authentication security score &middot; {failed} of {len(findings)} checks failed &middot; generated {ts}</p>
  </div>
  {cards}
  <footer>Credential &amp; Authentication Security Auditor &middot; IT 359 Group 5.
  Authorized lab testing only.</footer>
</body></html>"""
