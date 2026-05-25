from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box

console = Console()

BANNER = """
 ██████╗██╗      ██████╗ ██╗   ██╗██████╗ ██╗   ██╗
██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗╚██╗ ██╔╝
██║     ██║     ██║   ██║██║   ██║██║  ██║ ╚████╔╝
██║     ██║     ██║   ██║██║   ██║██║  ██║  ╚██╔╝
╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝   ██║
 ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝    ╚═╝
"""


def print_banner():
    console.print(Text(BANNER, style='bold cyan'))
    console.print('[dim]  aws infrastructure scanner + security analysis[/dim]\n')


def menu(title: str, options: list[tuple[str, str]]) -> str:
    """Print a numbered menu and return the selected key."""
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column(style='bold cyan', width=4)
    table.add_column(style='white')
    table.add_column(style='dim')

    for key, label, description in options:
        table.add_row(f'[{key}]', label, description)

    console.print(Panel(table, title=f'[bold]{title}[/bold]', border_style='cyan', padding=(1, 2)))

    valid = {k for k, _, _ in options}
    while True:
        choice = Prompt.ask('[bold cyan]>[/bold cyan]').strip().lower()
        if choice in valid:
            return choice
        console.print(f'[red]  invalid choice — enter {", ".join(sorted(valid))}[/red]')


def ask_aws_options() -> dict:
    """Prompt for AWS scan configuration."""
    console.print('\n[bold]aws scan options[/bold]\n')

    profile = Prompt.ask('  aws profile', default='default')
    profile = None if profile == 'default' else profile

    attempt_escalation = Confirm.ask('  attempt sts:AssumeRole on reachable roles', default=True)
    analyze = Confirm.ask('  send findings to claude code for analysis', default=False)
    out = Prompt.ask('  save json output to file (leave blank to skip)', default='')
    out = out.strip() or None
    html_out = Prompt.ask('  save html report to file (leave blank to skip)', default='')
    html_out = html_out.strip() or None

    return {'profile': profile, 'attempt_escalation': attempt_escalation,
            'analyze': analyze, 'out': out, 'html_out': html_out}


def ask_network_options() -> dict:
    """Prompt for network scan configuration."""
    console.print('\n[bold]network scan options[/bold]\n')

    raw = Prompt.ask('  target hosts (comma-separated ips or hostnames)')
    targets = [h.strip() for h in raw.split(',') if h.strip()]

    analyze = Confirm.ask('  send findings to claude code for analysis', default=False)
    out = Prompt.ask('  save json output to file (leave blank to skip)', default='')
    out = out.strip() or None

    return {'hosts': targets, 'scan_ec2': False, 'profile': None, 'analyze': analyze, 'out': out}


def ask_full_options() -> dict:
    """Prompt for full scan (aws + network) configuration."""
    console.print('\n[bold]full scan options[/bold]\n')

    profile = Prompt.ask('  aws profile', default='default')
    profile = None if profile == 'default' else profile

    scan_ec2 = Confirm.ask('  auto-scan ec2 public ips found in aws', default=True)

    extra_hosts = Prompt.ask('  additional hosts to scan (leave blank to skip)', default='')
    hosts = [h.strip() for h in extra_hosts.split(',') if h.strip()]

    attempt_escalation = Confirm.ask('  attempt sts:AssumeRole on reachable roles', default=True)
    analyze = Confirm.ask('  send findings to claude code for analysis', default=False)
    out = Prompt.ask('  save json output to file (leave blank to skip)', default='')
    out = out.strip() or None
    html_out = Prompt.ask('  save html report to file (leave blank to skip)', default='')
    html_out = html_out.strip() or None

    return {'profile': profile, 'scan_ec2': scan_ec2, 'hosts': hosts,
            'attempt_escalation': attempt_escalation,
            'analyze': analyze, 'out': out, 'html_out': html_out}


def get_scan_config() -> dict | None:
    """Main menu → returns scan config or None to exit."""
    print_banner()

    choice = menu('select scan type', [
        ('1', 'aws',           'enumerate iam, ec2, s3 across all regions'),
        ('2', 'network',       'port scan target hosts (requires nmap)'),
        ('3', 'full',          'aws + network — complete recon'),
        ('q', 'quit',          ''),
    ])

    if choice == 'q':
        return None
    if choice == '1':
        return {'mode': 'aws', **ask_aws_options()}
    if choice == '2':
        return {'mode': 'network', **ask_network_options()}
    if choice == '3':
        return {'mode': 'full', **ask_full_options()}
