from rich.console import Console

console = Console()

_SEV_COLOR = {'CRIT': 'red', 'HIGH': 'red', 'MED': 'yellow', 'LOW': 'white'}
_SEV_ORDER = ['CRIT', 'HIGH', 'MED', 'LOW']


def print_identity(identity: dict, scp_applied: bool = False) -> None:
    console.print(f"\n[bold][*] identity[/bold]")
    console.print(f"    account:   {identity['account_id']}")
    console.print(f"    arn:       {identity['arn']}")
    console.print(f"    type:      {identity['type']}")
    if scp_applied:
        console.print(f"    [dim]scps:      applied (permissions intersected with org SCPs)[/dim]")


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

    lambda_count = sum(
        len(r.get('functions', [])) for r in scan_data.get('lambda', {}).values() if isinstance(r, dict)
    )
    ssm_count = sum(
        len(r.get('parameters', [])) for r in scan_data.get('ssm', {}).values() if isinstance(r, dict)
    )
    secrets_count = sum(
        len(r.get('secrets', [])) for r in scan_data.get('secrets', {}).values() if isinstance(r, dict)
    )
    cfn_count = sum(
        len(r.get('stacks', [])) for r in scan_data.get('cloudformation', {}).values() if isinstance(r, dict)
    )
    rds_public = sum(
        len(r.get('public_snapshots', [])) for r in scan_data.get('rds', {}).values() if isinstance(r, dict)
    )

    if lambda_count:
        console.print(f"\n[bold][*] lambda[/bold]")
        console.print(f"    functions: {lambda_count}")
    if ssm_count:
        console.print(f"\n[bold][*] ssm[/bold]")
        console.print(f"    parameters: {ssm_count}")
    if secrets_count:
        console.print(f"\n[bold][*] secrets manager[/bold]")
        console.print(f"    secrets:   {secrets_count}")
    if cfn_count:
        console.print(f"\n[bold][*] cloudformation[/bold]")
        console.print(f"    stacks:    {cfn_count}")
    if rds_public:
        console.print(f"\n[bold][*] rds[/bold]")
        console.print(f"    [red]public snapshots: {rds_public}[/red]")


def print_privesc_paths(paths: list[dict], conditioned: set[str] = None) -> None:
    if not paths:
        return
    conditioned = conditioned or set()
    console.print(f'\n[bold red][*] privesc paths ({len(paths)})[/bold red]')
    for p in paths:
        color = 'red' if p['severity'] == 'CRIT' else 'yellow'
        needs = p.get('permissions_needed', [])
        cond_flag = ''
        if conditioned and any(
            any(c in cond.lower() for c in conditioned)
            for cond in [n.lower() for n in needs]
        ):
            cond_flag = ' [yellow][COND][/yellow]'
        console.print(f"    [[{color}]{p['severity']}[/{color}]] [bold]{p['technique']}[/bold]{cond_flag}")
        console.print(f"        {p['finding'].replace('privesc: ', '')}")
        console.print(f"        [dim]needs: {', '.join(needs)}[/dim]")
        console.print(f"        [dim cyan]{p.get('exploit_cmd', '')}[/dim cyan]")


def print_escalation_results(results: list[dict]) -> None:
    if not results:
        return
    console.print(f'\n[bold magenta][*] role assumption succeeded ({len(results)})[/bold magenta]')
    for r in results:
        chain = ' → '.join(a.split('/')[-1] for a in r['chain'])
        console.print(f'    [magenta]✓[/magenta] {chain}')
        console.print(f'        permissions: {r["permissions_count"]}')
        if r['privesc_paths']:
            console.print(f'        [red]privesc from here: {len(r["privesc_paths"])}[/red]')
            for p in r['privesc_paths'][:3]:
                console.print(f'            [{p["severity"]}] {p["technique"]}')


def print_findings(findings: list[dict]) -> None:
    console.print(f"\n[bold][*] findings[/bold]")
    if not findings:
        console.print(f"    [green]none[/green]")
        return
    for f in sorted(findings, key=lambda x: _SEV_ORDER.index(x['severity']) if x['severity'] in _SEV_ORDER else 99):
        color = _SEV_COLOR.get(f['severity'], 'white')
        console.print(f"    [[{color}]{f['severity']}[/{color}]] {f['resource']} → {f['finding']}")
