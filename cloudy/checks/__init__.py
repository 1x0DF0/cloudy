import networkx as nx


def run_service_checks(scan_data: dict) -> list[dict]:
    """Flat checks against raw scan data (SSM, Lambda, Secrets Manager)."""
    findings = []

    # SSM Parameter Store — accessible params with sensitive names
    for region_data in scan_data.get('ssm', {}).values():
        for p in region_data.get('parameters', []):
            if p.get('accessible') and p.get('sensitive'):
                findings.append({
                    'severity': 'CRIT',
                    'resource': f"ssm://{p['region']}/{p['name']}",
                    'finding': f"plaintext credential in SSM ({p['type']}): {p['value_preview'][:60]}…"
                    if p.get('value_preview') else f"sensitive SSM parameter accessible ({p['type']})",
                })
            elif p.get('accessible') and not p.get('sensitive'):
                pass  # readable but not obviously a credential — skip noise

    # Lambda — functions with flagged env var keys
    for region_data in scan_data.get('lambda', {}).values():
        for fn in region_data.get('functions', []):
            for key in fn.get('flagged_keys', []):
                val = fn['env_vars'].get(key, '')
                findings.append({
                    'severity': 'HIGH',
                    'resource': fn['arn'],
                    'finding': f"Lambda env var {key}={val[:60]}{'…' if len(val) > 60 else ''}",
                })

    # Secrets Manager — accessible secrets
    for region_data in scan_data.get('secrets', {}).values():
        for secret in region_data.get('secrets', []):
            if secret.get('accessible'):
                findings.append({
                    'severity': 'CRIT',
                    'resource': secret['arn'],
                    'finding': f"Secrets Manager secret readable: {secret.get('value_preview', '')[:60]}",
                })

    # CloudFormation — sensitive stack outputs
    for region_data in scan_data.get('cloudformation', {}).values():
        for stack in region_data.get('stacks', []):
            for out in stack.get('outputs', []):
                if out.get('sensitive'):
                    findings.append({
                        'severity': 'HIGH',
                        'resource': f"cfn://{stack['region']}/{stack['name']}",
                        'finding': f"stack output {out['key']} = {out['value'][:80]}",
                    })

    # RDS — publicly accessible instances
    for region_data in scan_data.get('rds', {}).values():
        for inst in region_data.get('instances', []):
            if inst.get('publicly_accessible'):
                findings.append({
                    'severity': 'HIGH',
                    'resource': f"rds://{inst['region']}/{inst['id']}",
                    'finding': f"{inst['engine']} publicly accessible at {inst['endpoint']}",
                })

    return findings


def run_all(graph: nx.DiGraph, scan_data: dict = None) -> list[dict]:
    findings = []
    findings.extend(_check_public_s3(graph))
    findings.extend(_check_open_security_groups(graph))
    findings.extend(_check_iam_no_mfa(graph))
    findings.extend(_check_wildcard_trust(graph))
    findings.extend(_check_role_chains(graph))
    findings.extend(_check_cross_account_trust(graph))
    if scan_data:
        findings.extend(_check_rds_public_snapshots(scan_data))
    return findings


def _check_public_s3(graph: nx.DiGraph) -> list[dict]:
    return [
        {'severity': 'CRIT', 'resource': node, 'finding': 'S3 bucket publicly accessible'}
        for node, attrs in graph.nodes(data=True)
        if attrs.get('type') == 's3' and attrs.get('is_public')
    ]


def _check_open_security_groups(graph: nx.DiGraph) -> list[dict]:
    findings = []
    for node, attrs in graph.nodes(data=True):
        if attrs.get('type') != 'security_group':
            continue
        for rule in attrs.get('ingress', []):
            proto = rule.get('IpProtocol', '-1')
            ports = f"{rule.get('FromPort', 0)}-{rule.get('ToPort', 65535)}"
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    findings.append({
                        'severity': 'HIGH',
                        'resource': node,
                        'finding': f'0.0.0.0/0 ingress {proto}:{ports}',
                    })
                    break
            for ip_range in rule.get('Ipv6Ranges', []):
                if ip_range.get('CidrIpv6') == '::/0':
                    findings.append({
                        'severity': 'HIGH',
                        'resource': node,
                        'finding': f'::/0 ingress {proto}:{ports}',
                    })
                    break
    return findings


def _check_iam_no_mfa(graph: nx.DiGraph) -> list[dict]:
    return [
        {'severity': 'MED', 'resource': node, 'finding': 'IAM user has no MFA device'}
        for node, attrs in graph.nodes(data=True)
        if attrs.get('type') == 'iam_user' and attrs.get('has_mfa') is False
    ]


def _check_wildcard_trust(graph: nx.DiGraph) -> list[dict]:
    return [
        {'severity': 'CRIT', 'resource': node,
         'finding': 'IAM role trust policy allows Principal: * (any entity can assume)'}
        for node, attrs in graph.nodes(data=True)
        if attrs.get('type') == 'iam_role' and attrs.get('wildcard_trust')
    ]


def _check_role_chains(graph: nx.DiGraph) -> list[dict]:
    findings = []
    role_nodes = {n for n, a in graph.nodes(data=True) if a.get('type') == 'iam_role'}
    for role in role_nodes:
        reachable = nx.descendants(graph, role) & role_nodes - {role}
        if reachable:
            findings.append({
                'severity': 'MED',
                'resource': role,
                'finding': f'role chain: reaches {len(reachable)} role(s) via AssumeRole',
            })
    return findings


def _check_cross_account_trust(graph: nx.DiGraph) -> list[dict]:
    findings = []
    for node, attrs in graph.nodes(data=True):
        if attrs.get('type') == 'iam_role' and attrs.get('cross_account_trust'):
            external = [
                pred for pred in graph.predecessors(node)
                if graph.nodes[pred].get('type') == 'external_principal'
            ]
            for ext in external:
                findings.append({
                    'severity': 'HIGH',
                    'resource': node,
                    'finding': f'cross-account trust: {ext} can assume this role',
                })
    return findings


def _check_rds_public_snapshots(scan_data: dict) -> list[dict]:
    findings = []
    for region_data in scan_data.get('rds', {}).values():
        if not isinstance(region_data, dict):
            continue
        for snap in region_data.get('public_snapshots', []):
            findings.append({
                'severity': 'CRIT',
                'resource': snap.get('arn', snap.get('id', '')),
                'finding': f"RDS snapshot publicly accessible: {snap['id']} ({snap['engine']}, {snap['size_gb']}GB)",
            })
    return findings
