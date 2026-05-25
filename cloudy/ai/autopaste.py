"""
Automatic clipboard paste/response loop.
Cloudy → Claude Code → Back to Cloudy
"""

import json
import time
import subprocess
import sys
from pathlib import Path

try:
    import pyperclip
    import pyautogui
except ImportError:
    print("[!] Missing dependencies. Install with:")
    print("    pip install pyperclip pyautogui")
    sys.exit(1)

RESPONSE_FILE = Path('cloudy_response.json')


def format_for_claude(findings: list[dict], account: str = None) -> str:
    """Format findings as readable text for pasting into Claude."""
    lines = ['=== AWS Security Findings ===\n']

    if account:
        lines.append(f'Account: {account}\n')

    by_sev = {}
    for f in findings:
        sev = f.get('severity', 'UNKNOWN')
        by_sev.setdefault(sev, []).append(f)

    for sev in ['CRIT', 'HIGH', 'MED', 'LOW']:
        if sev in by_sev:
            lines.append(f'\n[{sev}] ({len(by_sev[sev])})')
            for f in by_sev[sev]:
                lines.append(f"  • {f.get('resource', '?')} → {f.get('finding', '?')}")

    lines.append('\n\n---\nWhat do these findings mean? What should I do about them?')
    return '\n'.join(lines)


def send_to_claude_and_wait(findings: list[dict], account: str = None, timeout: int = 60) -> dict:
    """
    Copy findings to clipboard, trigger Claude Code paste, wait for response.
    """
    # Format findings as readable text
    text = format_for_claude(findings, account)

    # Copy to clipboard
    pyperclip.copy(text)
    print('[*] Findings copied to clipboard')

    # Focus Claude Code window (try to find it)
    print('[*] Focusing Claude Code window...')
    try:
        # On Windows, try to find and focus Claude Code
        subprocess.run(
            ['powershell', '-Command', 'Get-Process | Where-Object {$_.MainWindowTitle -like "*Claude*"} | ForEach-Object {$_.MainWindowHandle}'],
            check=False,
            capture_output=True
        )
    except Exception:
        pass

    # Wait a moment for window focus
    time.sleep(0.5)

    # Paste into chat
    print('[*] Pasting findings into Claude Code...')
    pyautogui.hotkey('ctrl', 'v')
    time.sleep(0.2)
    pyautogui.press('enter')

    # Clean up old response
    if RESPONSE_FILE.exists():
        RESPONSE_FILE.unlink()

    print(f'[*] Waiting for Claude Code analysis (timeout: {timeout}s)...')

    # Wait for response file
    start = time.time()
    while time.time() - start < timeout:
        if RESPONSE_FILE.exists():
            try:
                with open(RESPONSE_FILE) as f:
                    response = json.load(f)
                print('[+] Response received from Claude Code')
                return response
            except json.JSONDecodeError:
                time.sleep(1)
                continue
        time.sleep(1)

    print('[!] Timeout waiting for Claude Code response')
    return {'status': 'timeout'}


def write_response(analysis: str):
    """
    Claude Code calls this to write response back to cloudy.
    You paste your analysis as JSON into cloudy_response.json when prompted.
    """
    try:
        data = json.loads(analysis)
        with open(RESPONSE_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        print(f'[+] Response written to {RESPONSE_FILE}')
    except json.JSONDecodeError as e:
        print(f'[!] Invalid JSON: {e}')
