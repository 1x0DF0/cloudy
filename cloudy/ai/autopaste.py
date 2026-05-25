"""
Cloudy → Claude Code integration.

Flow:
  1. Write all findings + privesc paths + permissions to ~/.cloudy/findings.json
  2. Print a one-line prompt the user pastes into Claude Code
  3. Claude Code reads the file, writes analysis to ~/.cloudy/response.json
  4. Cloudy polls for the response file and renders it

No pyautogui — window-focus targeting is fragile. One paste is faster and reliable.
"""

import json
import time
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

console = Console()

CLOUDY_DIR = Path.home() / '.cloudy'
FINDINGS_FILE = CLOUDY_DIR / 'findings.json'
RESPONSE_FILE = CLOUDY_DIR / 'response.json'

_RESPONSE_SCHEMA = """{
  "status": "success",
  "summary": "2-sentence risk summary",
  "what_to_do": "highest-priority action",
  "paths": [
    {
      "technique": "...",
      "likelihood": "high|med|low",
      "stealth": "high|med|low",
      "cloudtrail_event": "iam:CreatePolicyVersion",
      "detection_note": "what a defender sees in CloudTrail",
      "remediation": "one-liner fix"
    }
  ],
  "recommended_order": ["technique1", "technique2"],
  "next_steps": ["...", "...", "..."]
}"""


def write_findings(findings: list[dict], privesc_paths: list[dict], scan_data: dict):
    CLOUDY_DIR.mkdir(exist_ok=True)
    payload = {
        'identity': scan_data.get('identity', {}),
        'scp_applied': scan_data.get('scp_applied', False),
        'permissions': sorted(scan_data.get('caller_permissions', set()), key=str),
        'conditioned_permissions': sorted(scan_data.get('caller_conditioned', set()), key=str),
        'findings': findings,
        'privesc_paths': [
            {k: v for k, v in p.items() if k != 'path'}  # strip nx path lists
            for p in privesc_paths
        ],
    }
    FINDINGS_FILE.write_text(json.dumps(payload, indent=2, default=str))


def _build_prompt() -> str:
    return (
        f'Read {FINDINGS_FILE} — it has AWS scan data: identity, effective IAM permissions '
        f'(post-SCP + boundary), misconfiguration findings, and IAM privesc paths with exploit commands. '
        f'Analyze everything. Cross-reference the raw permissions list for combinations not in the privesc paths. '
        f'Flag any conditioned_permissions that look exploitable despite their conditions. '
        f'Write your analysis as JSON to {RESPONSE_FILE} using the Write tool. '
        f'Schema: {_RESPONSE_SCHEMA}'
    )


def send_to_claude_and_wait(
    findings: list[dict],
    privesc_paths: list[dict] = None,
    scan_data: dict = None,
    account: str = None,
    timeout: int = 120,
) -> dict:
    privesc_paths = privesc_paths or []
    scan_data = scan_data or {}

    write_findings(findings, privesc_paths, scan_data)

    if RESPONSE_FILE.exists():
        RESPONSE_FILE.unlink()

    prompt = _build_prompt()

    console.print(Panel(
        f'[bold]paste this into Claude Code:[/bold]\n\n[cyan]{prompt}[/cyan]',
        title='[bold cyan]cloudy → claude[/bold cyan]',
        border_style='cyan',
        padding=(1, 2),
    ))
    console.print(f'[dim]waiting for {RESPONSE_FILE} (timeout: {timeout}s) ...[/dim]\n')

    start = time.time()
    while time.time() - start < timeout:
        if RESPONSE_FILE.exists():
            try:
                return json.loads(RESPONSE_FILE.read_text())
            except json.JSONDecodeError:
                pass
        time.sleep(1)

    return {'status': 'timeout'}
