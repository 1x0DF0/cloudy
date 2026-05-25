import networkx as nx


def run_all(graph: nx.DiGraph) -> list[dict]:
    findings = []
    findings.extend(_check_public_s3(graph))
    findings.extend(_check_open_security_groups(graph))
    findings.extend(_check_iam_no_mfa(graph))
    findings.extend(_check_wildcard_trust(graph))
    findings.extend(_check_role_chains(graph))
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
