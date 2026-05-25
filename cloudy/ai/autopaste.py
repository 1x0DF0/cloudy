"""
Cloudy → Claude Code automation.

Flow:
  1. Write findings + privesc paths to ~/.cloudy/findings.json
  2. Paste an explicit prompt into Claude Code telling it to read that file
     and write a structured JSON analysis to ~/.cloudy/response.json
  3. Poll ~/.cloudy/response.json until it appears or timeout
"""

import json
import time
from pathlib import Path

try:
    import pyperclip
    import pyautogui
except ImportError:
    import sys
    print('[!] pip install pyperclip pyautogui')
    sys.exit(1)

CLOUDY_DIR = Path.home() / '.cloudy'
FINDINGS_FILE = CLOUDY_DIR / 'findings.json'
RESPONSE_FILE = CLOUDY_DIR / 'response.json'

RESPONSE_SCHEMA = """{
  "status": "success",
  "summary": "2-sentence risk summary",
  "what_to_do": "top priority action",
  "paths": [
    {
      "technique": "...",
      "likelihood": "high|med|low",
      "stealth": "high|med|low",
      "cloudtrail_event": "iam:CreatePolicyVersion",
      "detection_note": "what a defender sees",
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
        'permissions': sorted(scan_data.get('caller_permissions', [])),
        'findings': findings,
        'privesc_paths': privesc_paths,
    }
    FINDINGS_FILE.write_text(json.dumps(payload, indent=2, default=str))


def _build_prompt() -> str:
    findings_path = str(FINDINGS_FILE)
    response_path = str(RESPONSE_FILE)
    return (
        f'Read the file at {findings_path}\n\n'
        f'It contains AWS security scan data: caller identity, effective IAM permissions, '
        f'misconfiguration findings, and privilege escalation paths with exploit commands.\n\n'
        f'Analyze everything — cross-reference the raw permissions list against the privesc paths '
        f'to find combinations that were not explicitly modeled. For each privesc path assess: '
        f'likelihood it works (given the other permissions), stealth (which CloudTrail event fires), '
        f'and one-liner remediation.\n\n'
        f'Write your full analysis as JSON to {response_path} using the Write tool. Schema:\n'
        f'{RESPONSE_SCHEMA}\n\n'
        f'After writing the file confirm with: "cloudy analysis written"'
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
    pyperclip.copy(prompt)

    time.sleep(0.3)
    pyautogui.hotkey('ctrl', 'v')
    time.sleep(0.2)
    pyautogui.press('enter')

    start = time.time()
    while time.time() - start < timeout:
        if RESPONSE_FILE.exists():
            try:
                return json.loads(RESPONSE_FILE.read_text())
            except json.JSONDecodeError:
                pass
        time.sleep(1)

    return {'status': 'timeout'}
