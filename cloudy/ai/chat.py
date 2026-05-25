"""
Interactive chat loop against Claude Code.
Uses ~/.cloudy/findings.json (from the last scan) as context.
User types a question → formatted prompt printed to paste into Claude Code →
Claude writes response to ~/.cloudy/response.json → cloudy shows it → repeat.
"""

import json
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()

CLOUDY_DIR = Path.home() / '.cloudy'
FINDINGS_FILE = CLOUDY_DIR / 'findings.json'
RESPONSE_FILE = CLOUDY_DIR / 'response.json'

_SCHEMA = '{"response": "your answer in plain text"}'


def _context_summary() -> str | None:
    if not FINDINGS_FILE.exists():
        return None
    try:
        data = json.loads(FINDINGS_FILE.read_text())
        identity = data.get('identity', {})
        findings = data.get('findings', [])
        paths = data.get('privesc_paths', [])
        crits = sum(1 for f in findings if f.get('severity') == 'CRIT')
        return (
            f"account: {identity.get('account_id', '?')}  "
            f"caller: {identity.get('arn', '?')}\n"
            f"findings: {len(findings)} ({crits} CRIT)  "
            f"privesc paths: {len(paths)}"
        )
    except Exception:
        return None


def _build_prompt(message: str, with_context: bool) -> str:
    context = f'Read {FINDINGS_FILE} for full scan context. ' if with_context else \
              f'Scan data is at {FINDINGS_FILE} if you need it. '
    return (
        f'{context}{message}\n\n'
        f'Write your response to {RESPONSE_FILE} using the Write tool. '
        f'Schema: {_SCHEMA}'
    )


def _poll(timeout: int = 120) -> str | None:
    start = time.time()
    while time.time() - start < timeout:
        if RESPONSE_FILE.exists():
            try:
                data = json.loads(RESPONSE_FILE.read_text())
                return data.get('response') or json.dumps(data, indent=2)
            except json.JSONDecodeError:
                pass
        time.sleep(1)
    return None


def chat_loop():
    console.print('\n[bold cyan][*] cloudy chat[/bold cyan]')

    summary = _context_summary()
    if summary:
        console.print(Panel(summary, title='[dim]last scan[/dim]',
                            border_style='dim', padding=(0, 2)))
    else:
        console.print('[dim]    no scan data — run a scan first for context[/dim]')

    console.print('[dim]    prefix with "ctx " to include full findings in prompt  |  exit to quit[/dim]\n')

    while True:
        try:
            message = Prompt.ask('[bold cyan]>[/bold cyan]').strip()
        except (KeyboardInterrupt, EOFError):
            break

        if not message or message.lower() in ('exit', 'quit', 'q'):
            break

        with_context = message.lower().startswith('ctx ')
        if with_context:
            message = message[4:].strip()

        if not message:
            continue

        if RESPONSE_FILE.exists():
            RESPONSE_FILE.unlink()

        prompt = _build_prompt(message, with_context)
        console.print(Panel(
            f'[cyan]{prompt}[/cyan]',
            title='[bold cyan]paste into Claude Code[/bold cyan]',
            border_style='cyan',
            padding=(1, 2),
        ))

        console.print('[dim]    waiting...[/dim]')
        response = _poll()

        if response:
            console.print(Panel(
                response,
                title='[bold cyan]claude[/bold cyan]',
                border_style='cyan',
                padding=(1, 2),
            ))
        else:
            console.print('[red][!] no response (120s timeout)[/red]')

        console.print()
