import networkx as nx


def _role_name_from_arn(arn: str) -> str:
    return arn.split('/')[-1]


def build_graph(scan_data: dict) -> nx.DiGraph:
    G = nx.DiGraph()

    for user in scan_data.get('iam', {}).get('users', []):
        G.add_node(user['Arn'], type='iam_user', name=user['UserName'],
                   has_mfa=user.get('has_mfa'))

    for role in scan_data.get('iam', {}).get('roles', []):
        G.add_node(role['Arn'], type='iam_role', name=role['RoleName'], wildcard_trust=False)
        trust = role.get('AssumeRolePolicyDocument', {})
        for stmt in trust.get('Statement', []):
            if stmt.get('Effect') != 'Allow':
                continue
            principal = stmt.get('Principal', {})
            if isinstance(principal, str):
                if principal == '*':
                    G.nodes[role['Arn']]['wildcard_trust'] = True
                else:
                    G.add_edge(principal, role['Arn'], relationship='can_assume')
                continue
            if isinstance(principal, dict):
                aws = principal.get('AWS', [])
                arns = [aws] if isinstance(aws, str) else aws
                for arn in arns:
                    if arn == '*':
                        G.nodes[role['Arn']]['wildcard_trust'] = True
                    elif arn:
                        G.add_edge(arn, role['Arn'], relationship='can_assume')

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

    return G
