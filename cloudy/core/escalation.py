"""
Role assumption engine.
For each role the caller can assume, try sts:AssumeRole, then run a
lightweight privesc-focused rescan under the new identity.
Max depth 2 to avoid infinite recursion on bidirectional trust chains.
"""

import boto3
from botocore.exceptions import ClientError

from providers.aws.identity import get_identity
from providers.aws.iam import get_caller_permissions
from checks.privesc import check_privesc


def _can_assume(role: dict, caller_arn: str) -> bool:
    trust = role.get('AssumeRolePolicyDocument', {})
    for stmt in trust.get('Statement', []):
        if stmt.get('Effect') != 'Allow':
            continue
        principal = stmt.get('Principal', {})
        if isinstance(principal, str):
            arns = [principal]
        elif isinstance(principal, dict):
            aws = principal.get('AWS', [])
            arns = [aws] if isinstance(aws, str) else list(aws)
        else:
            arns = []
        if caller_arn in arns or '*' in arns:
            return True
    return False


def try_assume_roles(
    session: boto3.Session,
    identity: dict,
    scan_data: dict,
    max_depth: int = 2,
    _depth: int = 0,
    _chain: list[str] | None = None,
) -> list[dict]:
    """
    Returns list of:
      {
        assumed_arn:      str,
        chain:            [caller_arn, ..., assumed_arn],
        identity:         dict,
        permissions_count: int,
        privesc_paths:    list[dict],
        success:          True,
      }
    Roles that raise AccessDenied on assume_role are silently skipped.
    """
    if _depth >= max_depth:
        return []

    caller_arn = identity.get('arn', '')
    chain = (_chain or [caller_arn])
    results = []
    sts = session.client('sts')

    for role in scan_data.get('iam', {}).get('roles', []):
        role_arn = role.get('Arn', '')
        if role_arn in chain:
            continue  # already in this chain
        if not _can_assume(role, caller_arn):
            continue

        try:
            resp = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName='cloudy-recon',
                DurationSeconds=900,
            )
            creds = resp['Credentials']
        except ClientError:
            continue  # AccessDenied or MFA required — skip

        assumed_session = boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
        )

        try:
            new_identity = get_identity(assumed_session)
            new_perms, _ = get_caller_permissions(assumed_session, new_identity)
        except Exception:
            continue

        # Reuse existing IAM enumeration (avoid re-enumerating all regions)
        partial_scan = {'identity': new_identity, 'iam': scan_data.get('iam', {})}
        privesc = check_privesc(new_perms, partial_scan)

        new_chain = chain + [role_arn]
        entry = {
            'assumed_arn': role_arn,
            'chain': new_chain,
            'identity': new_identity,
            'permissions_count': len(new_perms),
            'privesc_paths': privesc,
            'success': True,
        }
        results.append(entry)

        # Recurse — find further escalation from this role
        deeper = try_assume_roles(
            assumed_session, new_identity, scan_data,
            max_depth=max_depth, _depth=_depth + 1, _chain=new_chain,
        )
        results.extend(deeper)

    return results
