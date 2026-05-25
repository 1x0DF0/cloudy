import fnmatch
import networkx as nx


def _role_name_from_arn(arn: str) -> str:
    return arn.split('/')[-1]


def _add_trust_edge(G: nx.DiGraph, principal_arn: str, role_arn: str, account_id: str):
    """Add a can_assume edge, flagging cross-account principals."""
    cross = bool(account_id) and (
        f':{account_id}:' not in principal_arn and
        not principal_arn.startswith('arn:aws:iam::')  # service principals
    )
    if not G.has_node(principal_arn):
        G.add_node(principal_arn,
                   type='external_principal' if cross else 'unknown',
                   cross_account=cross)
    G.add_edge(principal_arn, role_arn, relationship='can_assume', cross_account=cross)
    if cross and G.has_node(role_arn):
        G.nodes[role_arn]['cross_account_trust'] = True


def _has(perms: set[str], action: str) -> bool:
    a = action.lower()
    for p in perms:
        if p == '*' or fnmatch.fnmatch(a, p):
            return True
    return False


def build_graph(scan_data: dict) -> nx.DiGraph:
    G = nx.DiGraph()
    account_id = scan_data.get('identity', {}).get('account_id', '')

    for user in scan_data.get('iam', {}).get('users', []):
        G.add_node(user['Arn'], type='iam_user', name=user['UserName'],
                   has_mfa=user.get('has_mfa'))

    for role in scan_data.get('iam', {}).get('roles', []):
        G.add_node(role['Arn'], type='iam_role', name=role['RoleName'],
                   wildcard_trust=False, cross_account_trust=False)
        trust = role.get('AssumeRolePolicyDocument', {})
        for stmt in trust.get('Statement', []):
            if stmt.get('Effect') != 'Allow':
                continue
            principal = stmt.get('Principal', {})
            if isinstance(principal, str):
                if principal == '*':
                    G.nodes[role['Arn']]['wildcard_trust'] = True
                else:
                    _add_trust_edge(G, principal, role['Arn'], account_id)
                continue
            if isinstance(principal, dict):
                aws = principal.get('AWS', [])
                arns = [aws] if isinstance(aws, str) else aws
                for arn in arns:
                    if arn == '*':
                        G.nodes[role['Arn']]['wildcard_trust'] = True
                    elif arn:
                        _add_trust_edge(G, arn, role['Arn'], account_id)

    role_by_name = {
        attrs['name']: node
        for node, attrs in G.nodes(data=True)
        if attrs.get('type') == 'iam_role'
    }

    for region, region_data in scan_data.get('ec2', {}).items():
        if not isinstance(region_data, dict) or 'error' in region_data:
            continue
        for sg in region_data.get('security_groups', []):
            G.add_node(sg['GroupId'], type='security_group', name=sg.get('GroupName', ''),
                       region=region, vpc_id=sg.get('VpcId'),
                       ingress=sg.get('IpPermissions', []))
        for vpc in region_data.get('vpcs', []):
            G.add_node(vpc['VpcId'], type='vpc', region=region, cidr=vpc.get('CidrBlock'))
        for inst in region_data.get('instances', []):
            G.add_node(inst['id'], type='ec2', region=region,
                       public_ip=inst.get('public_ip'),
                       private_ip=inst.get('private_ip'),
                       state=inst.get('state'))
            if inst.get('vpc_id') and G.has_node(inst['vpc_id']):
                G.add_edge(inst['id'], inst['vpc_id'], relationship='in_vpc')
            for sg_id in inst.get('security_groups', []):
                if G.has_node(sg_id):
                    G.add_edge(inst['id'], sg_id, relationship='in_sg')
            if inst.get('iam_profile'):
                role_name = _role_name_from_arn(inst['iam_profile'])
                role_arn = role_by_name.get(role_name)
                if role_arn:
                    G.add_edge(inst['id'], role_arn, relationship='has_role')

    for bucket in scan_data.get('s3', {}).get('buckets', []):
        G.add_node(f"s3://{bucket['name']}", type='s3', name=bucket['name'],
                   region=bucket.get('region'), is_public=bucket.get('is_public', False))

    # Lambda nodes + role edges
    for region_data in scan_data.get('lambda', {}).values():
        for fn in region_data.get('functions', []):
            G.add_node(fn['arn'], type='lambda', name=fn['name'],
                       region=fn['region'], flagged_keys=fn.get('flagged_keys', []))
            role_arn = fn.get('role')
            if role_arn and G.has_node(role_arn):
                G.add_edge(fn['arn'], role_arn, relationship='has_role')

    return G


# ---------------------------------------------------------------------------
# Privesc edge encoding — caller's permissions as directed graph edges
# ---------------------------------------------------------------------------

_HIGH_PRIV_POLICY_ARNS = {
    'arn:aws:iam::aws:policy/AdministratorAccess',
    'arn:aws:iam::aws:policy/PowerUserAccess',
}


def _admin_role_arns(G: nx.DiGraph) -> list[str]:
    """Nodes that are IAM roles with AdministratorAccess or PowerUserAccess attached."""
    return [
        n for n, a in G.nodes(data=True)
        if a.get('type') == 'iam_role' and a.get('high_priv')
    ]


def add_privesc_edges(G: nx.DiGraph, permissions: set[str], scan_data: dict):
    """
    Encode the caller's privesc-capable permissions as directed edges in the graph.
    This enables nx.all_simple_paths to find multi-hop escalation chains.

    Edges are labeled relationship='privesc:<technique>'.
    Caller node must already exist in the graph.
    """
    caller_arn = scan_data.get('identity', {}).get('arn', '')
    if not caller_arn or not G.has_node(caller_arn):
        return

    # Mark high-priv roles so path finder can target them
    for role in scan_data.get('iam', {}).get('roles', []):
        attached = {p.get('PolicyArn') for p in role.get('attached_policies', [])}
        if attached & _HIGH_PRIV_POLICY_ARNS:
            if G.has_node(role['Arn']):
                G.nodes[role['Arn']]['high_priv'] = True

    all_role_arns = [n for n, a in G.nodes(data=True) if a.get('type') == 'iam_role']

    # AttachRolePolicy / PutRolePolicy: caller can attach admin policy to any role
    if _has(permissions, 'iam:AttachRolePolicy') or _has(permissions, 'iam:PutRolePolicy'):
        technique = 'AttachRolePolicy' if _has(permissions, 'iam:AttachRolePolicy') else 'PutRolePolicy'
        for role_arn in all_role_arns:
            if not G.has_edge(caller_arn, role_arn):
                G.add_edge(caller_arn, role_arn,
                           relationship=f'privesc:{technique}',
                           requires=['iam:AttachRolePolicy or iam:PutRolePolicy', 'sts:AssumeRole'])

    # UpdateAssumeRolePolicy: caller can modify trust on any role to allow self
    if _has(permissions, 'iam:UpdateAssumeRolePolicy'):
        for role_arn in all_role_arns:
            if not G.has_edge(caller_arn, role_arn):
                G.add_edge(caller_arn, role_arn,
                           relationship='privesc:UpdateAssumeRolePolicy',
                           requires=['iam:UpdateAssumeRolePolicy', 'sts:AssumeRole'])

    # CreatePolicyVersion: caller can overwrite any customer-managed policy
    if _has(permissions, 'iam:CreatePolicyVersion'):
        account = scan_data.get('identity', {}).get('account_id', '')
        for policy in scan_data.get('iam', {}).get('policies', []):
            if policy.get('Arn', '').startswith(f'arn:aws:iam::{account}:policy/'):
                # Policies aren't nodes yet — add the edge to all roles using them
                # (simplified: edge from caller to any role as admin-policy vector)
                for role_arn in all_role_arns:
                    if not G.has_edge(caller_arn, role_arn):
                        G.add_edge(caller_arn, role_arn,
                                   relationship='privesc:CreatePolicyVersion',
                                   requires=['iam:CreatePolicyVersion'])
                break


def find_privesc_paths(G: nx.DiGraph, caller_arn: str, cutoff: int = 4) -> list[list[str]]:
    """
    Return all simple paths from caller to any high-priv role, cutoff hops.
    Each path is a list of node ARNs.
    Only includes paths that traverse at least one privesc edge.
    """
    if not G.has_node(caller_arn):
        return []

    admin_nodes = _admin_role_arns(G)
    paths = []
    for target in admin_nodes:
        if target == caller_arn:
            continue
        try:
            for path in nx.all_simple_paths(G, caller_arn, target, cutoff=cutoff):
                # Only include paths that use at least one privesc edge
                has_privesc = any(
                    G.edges[path[i], path[i + 1]].get('relationship', '').startswith('privesc:')
                    for i in range(len(path) - 1)
                )
                if has_privesc:
                    paths.append(path)
        except nx.NetworkXError:
            pass

    return paths
