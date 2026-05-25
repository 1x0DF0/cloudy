"""
HTML report export. Inline Jinja2 template — no external template files needed.
"""

from datetime import datetime, timezone
from pathlib import Path

try:
    from jinja2 import Environment
except ImportError:
    Environment = None  # type: ignore

import networkx as nx

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cloudy Report — {{ identity.account_id }}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }
  h1 { color: #58a6ff; font-size: 1.4rem; margin-bottom: 0.3rem; }
  h2 { color: #58a6ff; font-size: 1rem; margin: 1.5rem 0 0.5rem; border-bottom: 1px solid #21262d; padding-bottom: 0.3rem; }
  .meta { color: #8b949e; font-size: 0.85rem; margin-bottom: 2rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th { text-align: left; padding: 0.4rem 0.6rem; color: #8b949e; border-bottom: 1px solid #21262d; }
  td { padding: 0.4rem 0.6rem; border-bottom: 1px solid #161b22; vertical-align: top; word-break: break-all; }
  tr:hover td { background: #161b22; }
  .CRIT { color: #f85149; font-weight: bold; }
  .HIGH { color: #f85149; }
  .MED  { color: #e3b341; }
  .LOW  { color: #8b949e; }
  .tag  { display: inline-block; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.75rem;
          background: #21262d; margin-right: 0.3rem; }
  .tag-crit { background: #3d1a1a; color: #f85149; }
  .tag-high { background: #3d1a1a; color: #f85149; }
  .tag-med  { background: #3d2a00; color: #e3b341; }
  .cmd  { color: #79c0ff; font-size: 0.78rem; }
  .chain { color: #7ee787; }
  .section { margin-bottom: 2rem; }
  .none { color: #3d4450; }
  .sev-badge { display: inline-block; width: 4rem; text-align: center; padding: 0.1rem 0; border-radius: 3px; font-size: 0.75rem; font-weight: bold; }
  .sev-CRIT { background: #3d1a1a; color: #f85149; }
  .sev-HIGH { background: #2d1a1a; color: #e06c75; }
  .sev-MED  { background: #2d2200; color: #e3b341; }
  .sev-LOW  { background: #1e2228; color: #8b949e; }
</style>
</head>
<body>

<h1>cloudy // aws security scan</h1>
<div class="meta">
  account: {{ identity.account_id }} &nbsp;|&nbsp;
  arn: {{ identity.arn }} &nbsp;|&nbsp;
  type: {{ identity.type }} &nbsp;|&nbsp;
  generated: {{ timestamp }}
  {% if scp_applied %}&nbsp;|&nbsp; <span style="color:#7ee787">SCPs applied</span>{% endif %}
</div>

<div class="section">
<h2>summary</h2>
<table>
  <tr><th>resource</th><th>count</th></tr>
  <tr><td>iam users</td><td>{{ summary.iam_users }}</td></tr>
  <tr><td>iam roles</td><td>{{ summary.iam_roles }}</td></tr>
  <tr><td>iam policies (local)</td><td>{{ summary.iam_policies }}</td></tr>
  <tr><td>ec2 instances</td><td>{{ summary.ec2_instances }}</td></tr>
  <tr><td>s3 buckets</td><td>{{ summary.s3_buckets }} ({{ summary.s3_public }} public)</td></tr>
  <tr><td>lambda functions</td><td>{{ summary.lambda_functions }}</td></tr>
  <tr><td>ssm parameters</td><td>{{ summary.ssm_parameters }}</td></tr>
  <tr><td>secrets manager</td><td>{{ summary.secrets }}</td></tr>
  <tr><td>cfn stacks</td><td>{{ summary.cfn_stacks }}</td></tr>
  <tr><td>rds public snapshots</td><td>{{ summary.rds_public_snapshots }}</td></tr>
</table>
</div>

<div class="section">
<h2>findings ({{ findings | length }})</h2>
{% if findings %}
<table>
  <tr><th>sev</th><th>resource</th><th>finding</th></tr>
  {% for f in findings %}
  <tr>
    <td><span class="sev-badge sev-{{ f.severity }}">{{ f.severity }}</span></td>
    <td>{{ f.resource }}</td>
    <td>{{ f.finding }}</td>
  </tr>
  {% endfor %}
</table>
{% else %}<p class="none">none</p>{% endif %}
</div>

<div class="section">
<h2>privilege escalation paths ({{ privesc_paths | length }})</h2>
{% if privesc_paths %}
<table>
  <tr><th>sev</th><th>technique</th><th>needs</th><th>exploit</th></tr>
  {% for p in privesc_paths %}
  <tr>
    <td><span class="sev-badge sev-{{ p.severity }}">{{ p.severity }}</span></td>
    <td><strong>{{ p.technique }}</strong><br><small>{{ p.finding | replace('privesc: ', '') }}</small></td>
    <td>{% for n in p.permissions_needed %}<span class="tag">{{ n }}</span>{% endfor %}</td>
    <td class="cmd">{{ p.exploit_cmd }}</td>
  </tr>
  {% endfor %}
</table>
{% else %}<p class="none">none</p>{% endif %}
</div>

{% if escalation_results %}
<div class="section">
<h2>assumed roles</h2>
<table>
  <tr><th>chain</th><th>permissions</th><th>further privesc</th></tr>
  {% for r in escalation_results %}
  <tr>
    <td class="chain">{{ r.chain | join(' → ', attribute='split("/")[-1]') }}</td>
    <td>{{ r.permissions_count }}</td>
    <td>
      {% for p in r.privesc_paths %}
        <span class="tag tag-{{ p.severity | lower }}">{{ p.technique }}</span>
      {% endfor %}
      {% if not r.privesc_paths %}<span class="none">—</span>{% endif %}
    </td>
  </tr>
  {% endfor %}
</table>
</div>
{% endif %}

</body>
</html>
"""


def export_html(
    scan_data: dict,
    findings: list[dict],
    privesc_paths: list[dict],
    escalation_results: list[dict],
    graph: nx.DiGraph,
    path: str,
) -> None:
    if Environment is None:
        raise ImportError('jinja2 required: pip install jinja2')

    identity = scan_data.get('identity', {})
    iam = scan_data.get('iam', {})
    ec2_all = scan_data.get('ec2', {})
    s3 = scan_data.get('s3', {})

    lambda_count = sum(
        len(r.get('functions', [])) for r in scan_data.get('lambda', {}).values()
        if isinstance(r, dict)
    )
    ssm_count = sum(
        len(r.get('parameters', [])) for r in scan_data.get('ssm', {}).values()
        if isinstance(r, dict)
    )
    secrets_count = sum(
        len(r.get('secrets', [])) for r in scan_data.get('secrets', {}).values()
        if isinstance(r, dict)
    )
    cfn_count = sum(
        len(r.get('stacks', [])) for r in scan_data.get('cloudformation', {}).values()
        if isinstance(r, dict)
    )
    rds_public = sum(
        len(r.get('public_snapshots', [])) for r in scan_data.get('rds', {}).values()
        if isinstance(r, dict)
    )

    summary = {
        'iam_users': len(iam.get('users', [])),
        'iam_roles': len(iam.get('roles', [])),
        'iam_policies': len(iam.get('policies', [])),
        'ec2_instances': sum(
            len(r.get('instances', [])) for r in ec2_all.values()
            if isinstance(r, dict) and 'error' not in r
        ),
        's3_buckets': len(s3.get('buckets', [])),
        's3_public': len([b for b in s3.get('buckets', []) if b.get('is_public')]),
        'lambda_functions': lambda_count,
        'ssm_parameters': ssm_count,
        'secrets': secrets_count,
        'cfn_stacks': cfn_count,
        'rds_public_snapshots': rds_public,
    }

    env = Environment()
    # Jinja2 filter for the chain display
    env.filters['join'] = lambda lst, sep, attribute=None: sep.join(
        getattr(item, attribute.split('(')[0], item) if attribute else str(item)
        for item in lst
    )

    # Simpler: just pre-process the chain in Python
    processed_escalation = []
    for r in escalation_results:
        processed_escalation.append({
            **r,
            'chain_display': ' → '.join(a.split('/')[-1] for a in r['chain']),
        })

    # Re-render template with simpler chain display
    simple_template = _TEMPLATE.replace(
        "{{ r.chain | join(' → ', attribute='split(\"/\")[-1]') }}",
        "{{ r.chain_display }}"
    )

    tmpl = env.from_string(simple_template)
    html = tmpl.render(
        identity=type('I', (), identity)(),
        timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        scp_applied=scan_data.get('scp_applied', False),
        summary=type('S', (), summary)(),
        findings=sorted(findings, key=lambda x: ['CRIT', 'HIGH', 'MED', 'LOW'].index(x.get('severity', 'LOW')) if x.get('severity') in ['CRIT', 'HIGH', 'MED', 'LOW'] else 99),
        privesc_paths=privesc_paths,
        escalation_results=processed_escalation,
    )

    Path(path).write_text(html, encoding='utf-8')
