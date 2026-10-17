"""Report generation (JSON, HTML, Markdown, SARIF, CSV) for scan results."""

import csv
import html
import io
import json
import re
from collections import Counter
from typing import Any, Dict, List

from core.config import APP_VERSION
from models.scan_result import ScanResult
from models.vulnerability import Severity, Vulnerability


SEVERITY_COLORS = {
    'CRITICAL': '#ef4444',
    'HIGH': '#f97316',
    'MEDIUM': '#eab308',
    'LOW': '#06b6d4',
}

SARIF_LEVELS = {
    Severity.CRITICAL: 'error',
    Severity.HIGH: 'error',
    Severity.MEDIUM: 'warning',
    Severity.LOW: 'note',
}

# GitHub code scanning uses this numeric property to bucket severities
SARIF_SECURITY_SEVERITY = {
    Severity.CRITICAL: '9.5',
    Severity.HIGH: '8.0',
    Severity.MEDIUM: '5.5',
    Severity.LOW: '3.0',
}

FORMATS = ('json', 'html', 'markdown', 'sarif', 'csv')
EXTENSIONS = {'json': 'json', 'html': 'html', 'markdown': 'md', 'sarif': 'sarif', 'csv': 'csv'}


def export(result: ScanResult, format_type: str) -> str:
    """Render a scan result in the requested format."""
    format_type = format_type.lower()
    if format_type == 'md':
        format_type = 'markdown'
    renderers = {
        'json': to_json,
        'html': to_html,
        'markdown': to_markdown,
        'sarif': to_sarif,
        'csv': to_csv,
    }
    if format_type not in renderers:
        raise ValueError(f"Unsupported export format: {format_type}. Choose from {', '.join(FORMATS)}")
    return renderers[format_type](result)


def _score(result: ScanResult) -> Dict[str, Any]:
    score = result.metadata.get('score')
    if score:
        return score
    from scoring.score_engine import ScoreEngine
    s = ScoreEngine().calculate(result.vulnerabilities)
    return {'score': s.score, 'risk_level': s.risk_level, 'grade': s.grade,
            'breakdown': s.breakdown, 'recommendations': s.recommendations}


def _location(v: Vulnerability) -> str:
    rel = v.metadata.get('relative_path')
    if rel:
        return f"{rel}:{v.line_number}" if v.line_number else rel
    return v.get_location_string() if v.file_path else (v.metadata.get('url') or 'Web application')


def rule_id(v: Vulnerability) -> str:
    """Stable rule identifier for a finding."""
    rule = v.metadata.get('rule') or v.metadata.get('pattern')
    if not rule:
        rule = re.sub(r'[^a-z0-9]+', '-', re.sub(r':.*$', '', v.title).lower()).strip('-')
    return f"{v.scanner_source}/{rule}"


# ---------------------------------------------------------------------- JSON

def to_json(result: ScanResult) -> str:
    data = result.to_dict()
    data['summary'] = result.get_summary()
    data['tool'] = {'name': 'SecureMySite', 'version': APP_VERSION}
    return json.dumps(data, indent=2, default=str)


# ---------------------------------------------------------------------- CSV

def to_csv(result: ScanResult) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(['severity', 'title', 'file', 'line', 'cwe', 'category', 'scanner', 'description',
                     'remediation', 'fingerprint'])
    for v in result.vulnerabilities:
        writer.writerow([
            v.severity.name, v.title, v.metadata.get('relative_path') or (str(v.file_path) if v.file_path else ''),
            v.line_number or '', v.cwe_id or '', v.category.name, v.scanner_source, v.description,
            v.remediation, v.metadata.get('fingerprint', ''),
        ])
    return buffer.getvalue()


# ---------------------------------------------------------------------- SARIF

def to_sarif(result: ScanResult) -> str:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for v in result.vulnerabilities:
        rid = rule_id(v)
        if rid not in rules:
            rule: Dict[str, Any] = {
                'id': rid,
                'name': re.sub(r'[^A-Za-z0-9]', '', v.title.title())[:64] or 'Finding',
                'shortDescription': {'text': re.sub(r':.*$', '', v.title)},
                'fullDescription': {'text': v.description},
                'help': {'text': v.remediation, 'markdown': f"**Fix:** {v.remediation}"},
                'defaultConfiguration': {'level': SARIF_LEVELS[v.severity]},
                'properties': {
                    'tags': ['security', v.category.name.lower()],
                    'security-severity': SARIF_SECURITY_SEVERITY[v.severity],
                },
            }
            if v.cwe_id:
                rule['properties']['tags'].append(f"external/cwe/{v.cwe_id.lower()}")
                rule['helpUri'] = f"https://cwe.mitre.org/data/definitions/{v.cwe_id.split('-')[-1]}.html"
            rules[rid] = rule

        entry: Dict[str, Any] = {
            'ruleId': rid,
            'level': SARIF_LEVELS[v.severity],
            'message': {'text': f"{v.title}: {v.description}"},
            'properties': {'severity': v.severity.name, 'scanner': v.scanner_source},
        }
        rel = v.metadata.get('relative_path')
        if rel:
            region: Dict[str, Any] = {'startLine': v.line_number or 1}
            if v.column_start is not None:
                region['startColumn'] = v.column_start + 1
            entry['locations'] = [{
                'physicalLocation': {
                    'artifactLocation': {'uri': rel, 'uriBaseId': '%SRCROOT%'},
                    'region': region,
                }
            }]
        else:
            target = v.metadata.get('url') or result.metadata.get('target') or '.'
            entry['locations'] = [{'physicalLocation': {'artifactLocation': {'uri': str(target).split(' ')[0]}}}]
        if v.metadata.get('fingerprint'):
            entry['partialFingerprints'] = {'securemysite/v1': v.metadata['fingerprint']}
        results.append(entry)

    sarif = {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'SecureMySite',
                    'version': APP_VERSION,
                    'informationUri': 'https://github.com/tworjaga/SecureMySite',
                    'rules': list(rules.values()),
                }
            },
            **({} if result.metadata.get('scan_type') == 'domain' else
               {'originalUriBaseIds': {'%SRCROOT%': {'uri': result.project_path.resolve().as_uri() + '/'}}}),
            'results': results,
        }],
    }
    return json.dumps(sarif, indent=2)


# ---------------------------------------------------------------------- Markdown

def to_markdown(result: ScanResult) -> str:
    score = _score(result)
    summary = result.get_summary()
    out = [
        '# Security Analysis Report',
        '',
        f"Generated by SecureMySite {APP_VERSION} on {result.scan_start_time:%Y-%m-%d %H:%M}",
        '',
        '## Summary',
        '',
        f"- **Score:** {score['score']}/100 ({score['grade']}, {score['risk_level']})",
        *(([f"- **Domain:** `{result.metadata.get('target')}`"]) if result.metadata.get('scan_type') == 'domain'
          else [f"- **Project:** `{result.project_path}`", f"- **Files scanned:** {result.files_scanned}"]),
        f"- **Findings:** {summary['total_vulnerabilities']}",
        '',
        '| Severity | Count |',
        '|----------|-------|',
    ]
    for sev in Severity:
        out.append(f"| {sev.name} | {len(result.get_vulnerabilities_by_severity(sev))} |")
    out += ['', '## Findings', '']

    if not result.vulnerabilities:
        out.append('No issues found.')
    for i, v in enumerate(result.vulnerabilities, 1):
        out += [
            f"### {i}. [{v.severity.name}] {v.title}",
            '',
            f"- **Location:** `{_location(v)}`",
        ]
        if v.cwe_id:
            out.append(f"- **CWE:** [{v.cwe_id}](https://cwe.mitre.org/data/definitions/{v.cwe_id.split('-')[-1]}.html)")
        out += ['', v.description, '', f"**Fix:** {v.remediation}", '']
        if v.code_snippet:
            fence = '````' if '```' in v.code_snippet else '```'
            out += [fence, v.code_snippet, fence, '']

    if score.get('recommendations'):
        out += ['## Recommendations', '']
        out += [f"- {rec}" for rec in score['recommendations']]
    return '\n'.join(out) + '\n'


# ---------------------------------------------------------------------- HTML

def to_html(result: ScanResult) -> str:
    """Self-contained HTML report. Every dynamic value is HTML-escaped."""
    e = html.escape
    score = _score(result)
    counts = Counter(v.severity.name for v in result.vulnerabilities)
    score_color = (
        '#10b981' if score['score'] >= 80 else '#f59e0b' if score['score'] >= 60
        else '#f97316' if score['score'] >= 40 else '#ef4444'
    )

    cards = []
    for v in result.vulnerabilities:
        color = SEVERITY_COLORS[v.severity.name]
        cwe = ''
        if v.cwe_id:
            cwe = (f'<a class="cwe" href="https://cwe.mitre.org/data/definitions/{e(v.cwe_id.split("-")[-1])}.html" '
                   f'target="_blank" rel="noopener noreferrer">{e(v.cwe_id)}</a>')
        snippet = f'<pre><code>{e(v.code_snippet)}</code></pre>' if v.code_snippet else ''
        search = e(f"{v.title} {_location(v)} {v.description}".lower())
        cards.append(f"""
    <article class="finding" data-severity="{v.severity.name}" data-search="{search}" style="--sev:{color}">
      <header><span class="badge">{v.severity.name}</span><h3>{e(v.title)}</h3>{cwe}</header>
      <div class="loc">{e(_location(v))} &middot; {e(v.scanner_source)}</div>
      <p>{e(v.description)}</p>
      <p class="fix"><strong>Fix:</strong> {e(v.remediation)}</p>
      {snippet}
    </article>""")

    recs = ''.join(f'<li>{e(r)}</li>' for r in score.get('recommendations', []))
    sev_buttons = ''.join(
        f'<button class="chip on" data-sev="{s.name}" style="--sev:{SEVERITY_COLORS[s.name]}">'
        f'{s.name.title()} <b>{counts.get(s.name, 0)}</b></button>'
        for s in Severity
    )
    errors = ''
    if result.errors:
        errors = '<details class="errors"><summary>Scan warnings ({})</summary><ul>{}</ul></details>'.format(
            len(result.errors), ''.join(f'<li>{e(err)}</li>' for err in result.errors[:200]))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Security Report - {e(result.project_path.name)}</title>
<style>
  :root {{ --bg:#0d1117; --surface:#161b22; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --code:#0b0f14; }}
  @media (prefers-color-scheme: light) {{
    :root {{ --bg:#f6f8fa; --surface:#ffffff; --border:#d0d7de; --text:#1f2328; --muted:#59636e; --code:#f6f8fa; }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; background:var(--bg); color:var(--text); }}
  main {{ max-width:1000px; margin:0 auto; padding:32px 16px 64px; }}
  .hero {{ display:flex; gap:28px; align-items:center; flex-wrap:wrap; background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:24px; }}
  .score {{ font-size:56px; font-weight:800; color:{score_color}; line-height:1; }}
  .score small {{ font-size:18px; color:var(--muted); font-weight:500; }}
  .meta {{ color:var(--muted); font-size:13px; }}
  h1 {{ margin:0 0 4px; font-size:22px; }}
  .toolbar {{ display:flex; flex-wrap:wrap; gap:8px; margin:24px 0 12px; align-items:center; }}
  .chip {{ border:1px solid var(--sev); color:var(--sev); background:transparent; border-radius:999px; padding:5px 12px; cursor:pointer; font:inherit; font-size:13px; }}
  .chip.on {{ background:var(--sev); color:#fff; }}
  input[type=search] {{ flex:1; min-width:180px; padding:8px 12px; border-radius:8px; border:1px solid var(--border); background:var(--surface); color:var(--text); font:inherit; }}
  .finding {{ background:var(--surface); border:1px solid var(--border); border-left:4px solid var(--sev); border-radius:10px; padding:16px 18px; margin:12px 0; }}
  .finding header {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
  .finding h3 {{ margin:0; font-size:16px; flex:1; }}
  .badge {{ background:var(--sev); color:#fff; font-size:11px; font-weight:700; border-radius:999px; padding:2px 9px; }}
  .cwe {{ color:var(--muted); font-size:12px; }}
  .loc {{ font-family:ui-monospace,Consolas,monospace; font-size:12px; color:var(--muted); margin:6px 0; word-break:break-all; }}
  .fix {{ color:#10b981; }}
  pre {{ background:var(--code); border:1px solid var(--border); border-radius:8px; padding:12px; overflow-x:auto; font-size:12.5px; }}
  .errors {{ margin-top:24px; color:var(--muted); }}
  .empty {{ text-align:center; color:var(--muted); padding:40px; }}
</style>
</head>
<body>
<main>
  <section class="hero">
    <div class="score">{score['score']}<small>/100</small></div>
    <div>
      <h1>Security Report &middot; {e(result.project_path.name)}</h1>
      <div>Grade <strong>{e(str(score['grade']))}</strong> &middot; {e(str(score['risk_level']))}</div>
      <div class="meta">{len(result.vulnerabilities)} findings {('for domain ' + e(str(result.metadata.get('target')))) if result.metadata.get('scan_type') == 'domain' else f'in {result.files_scanned} files'} &middot;
        {result.scan_start_time:%Y-%m-%d %H:%M} &middot; SecureMySite {e(APP_VERSION)}</div>
      <div class="meta">{e(str(result.project_path))}</div>
    </div>
  </section>
  <div class="toolbar">{sev_buttons}<input type="search" id="q" placeholder="Filter findings..."></div>
  <section id="list">{''.join(cards) or '<p class="empty">No issues found.</p>'}</section>
  {'<h2>Recommendations</h2><ul>' + recs + '</ul>' if recs else ''}
  {errors}
</main>
<script>
  const chips = document.querySelectorAll('.chip');
  const q = document.getElementById('q');
  function apply() {{
    const on = new Set([...chips].filter(c => c.classList.contains('on')).map(c => c.dataset.sev));
    const term = q.value.toLowerCase();
    document.querySelectorAll('.finding').forEach(f => {{
      f.hidden = !(on.has(f.dataset.severity) && f.dataset.search.includes(term));
    }});
  }}
  chips.forEach(c => c.addEventListener('click', () => {{ c.classList.toggle('on'); apply(); }}));
  q.addEventListener('input', apply);
</script>
</body>
</html>
"""
