from rich.console import Console

from ui import get_scan_config
from core.engine import ScanEngine
from core.graph import build_graph
from checks import run_all
from output.terminal import print_identity, print_summary, print_findings
from output.json_export import export_json
from providers.network.nmap import scan_hosts, findings_from_scans, is_nmap_installed
from ai.autopaste import send_to_claude_and_wait

console = Console()


def run_aws(config: dict):
    engine = ScanEngine(profile=config.get('profile'))
    scan_data = engine.run()

    if 'error' in scan_data:
        err = scan_data['error']
        if err == 'no_credentials':
            console.print('[red][!] No AWS credentials found.[/red]')
            console.print('[dim]    aws configure  — set up credentials[/dim]')
        else:
            console.print(f'[red][!] {err}[/red]')
        return None, None, None

    print_identity(scan_data['identity'])
    print_summary(scan_data)

    graph = build_graph(scan_data)
    findings = run_all(graph)
    return scan_data, graph, findings


def run_network(targets: list[str]) -> list[dict]:
    if not is_nmap_installed():
        console.print('[yellow][!] nmap not in PATH — skipping network scan[/yellow]')
        return []
    console.print(f'\n[bold][*] network[/bold]')
    console.print(f'    hosts: {len(targets)}')
    net_results = scan_hosts(targets)
    return findings_from_scans(net_results)


def main():
    config = get_scan_config()
    if config is None:
        return

    mode = config['mode']
    scan_data, graph, findings = None, None, []

    if mode in ('aws', 'full'):
        scan_data, graph, findings = run_aws(config)
        if scan_data is None:
            return
        findings = findings or []

    if mode in ('network', 'full'):
        targets = list(config.get('hosts') or [])

        if mode == 'full' and config.get('scan_ec2') and scan_data:
            for region_data in scan_data.get('ec2', {}).values():
                if isinstance(region_data, dict) and 'error' not in region_data:
                    for inst in region_data.get('instances', []):
                        if inst.get('public_ip'):
                            targets.append(inst['public_ip'])

        if targets:
            findings += run_network(targets)

    print_findings(findings)

    if config.get('out'):
        export_json(scan_data or {}, findings, graph, config['out'])
        console.print(f'\n[dim]→ {config["out"]}[/dim]')

    if config.get('analyze'):
        account = (scan_data or {}).get('identity', {}).get('account_id', 'unknown')
        console.print('\n[bold cyan][*] sending to Claude Code...[/bold cyan]')
        response = send_to_claude_and_wait(findings, account=account)

        if response.get('status') != 'timeout':
            console.print('\n[bold cyan][*] Claude Code analysis[/bold cyan]')
            if 'summary' in response:
                console.print(f"\n{response['summary']}")
            if 'what_to_do' in response:
                console.print(f"\n[bold yellow]what to do:[/bold yellow]\n{response['what_to_do']}")
            if 'next_steps' in response:
                console.print('\n[bold yellow]next steps:[/bold yellow]')
                for step in response.get('next_steps', []):
                    console.print(f'  → {step}')
        else:
            console.print('[red][!] no response from Claude Code[/red]')


if __name__ == '__main__':
    main()
