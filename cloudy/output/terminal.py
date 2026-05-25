from rich.console import Console

console = Console()

_SEV_COLOR = {'CRIT': 'red', 'HIGH': 'red', 'MED': 'yellow', 'LOW': 'white'}
_SEV_ORDER = ['CRIT', 'HIGH', 'MED', 'LOW']


def print_identity(identity: dict) -> None:
    console.print(f"\n[bold][*] identity[/bold]")
    console.print(f"    account:   {identity['account_id']}")
    console.print(f"    arn:       {identity['arn']}")
    console.print(f"    type:      {identity['type']}")


def print_summary(scan_data: dict) -> None:
    iam = scan_data.get('iam', {})
    ec2_all = scan_data.get('ec2', {})
    s3 = scan_data.get('s3', {})

    total_instances = sum(
        len(r.get('instances', [])) for r in ec2_all.values() if isinstance(r, dict) and 'error' not in r
    )
    total_sgs = sum(
        len(r.get('security_groups', [])) for r in ec2_all.values() if isinstance(r, dict) and 'error' not in r
    )

    console.print(f"\n[bold][*] iam[/bold]")
    console.print(f"    users:     {len(iam.get('users', []))}")
    console.print(f"    roles:     {len(iam.get('roles', []))}")
    console.print(f"    policies:  {len(iam.get('policies', []))} (local)")
    for err in iam.get('errors', []):
        console.print(f"    [yellow][!] {err}[/yellow]")

    console.print(f"\n[bold][*] ec2[/bold]")
    console.print(f"    instances: {total_instances}")
    console.print(f"    sgs:       {total_sgs}")

    console.print(f"\n[bold][*] s3[/bold]")
    buckets = s3.get('buckets', [])
    public = [b for b in buckets if b.get('is_public')]
    console.print(f"    buckets:   {len(buckets)}")
    if public:
        console.print(f"    [red]public:    {len(public)}[/red]")


def print_privesc_paths(paths: list[dict]) -> None:
    if not paths:
        return
    console.print(f'\n[bold red][*] privesc paths ({len(paths)})[/bold red]')
    for p in paths:
        color = 'red' if p['severity'] == 'CRIT' else 'yellow'
        console.print(f"    [[{color}]{p['severity']}[/{color}]] [bold]{p['technique']}[/bold]")
        console.print(f"        {p['finding'].replace('privesc: ', '')}")
        console.print(f"        [dim]needs: {', '.join(p.get('permissions_needed', []))}[/dim]")
        console.print(f"        [dim cyan]{p.get('exploit_cmd', '')}[/dim cyan]")


def print_findings(findings: list[dict]) -> None:
    console.print(f"\n[bold][*] findings[/bold]")
    if not findings:
        console.print(f"    [green]none[/green]")
        return
    for f in sorted(findings, key=lambda x: _SEV_ORDER.index(x['severity']) if x['severity'] in _SEV_ORDER else 99):
        color = _SEV_COLOR.get(f['severity'], 'white')
        console.print(f"    [[{color}]{f['severity']}[/{color}]] {f['resource']} → {f['finding']}")
