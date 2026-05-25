import boto3
from botocore.exceptions import ClientError


def _expand_actions(actions) -> set[str]:
    if isinstance(actions, str):
        actions = [actions]
    return {a.lower() for a in actions}


def _extract_allows(policy_doc: dict) -> set[str]:
    allows = set()
    for stmt in policy_doc.get('Statement', []):
        if stmt.get('Effect') != 'Allow':
            continue
        allows |= _expand_actions(stmt.get('Action', []))
    return allows


def _extract_conditioned_allows(policy_doc: dict) -> set[str]:
    """Actions that are Allowed but gated behind a Condition block."""
    conditioned = set()
    for stmt in policy_doc.get('Statement', []):
        if stmt.get('Effect') != 'Allow':
            continue
        if stmt.get('Condition'):
            conditioned |= _expand_actions(stmt.get('Action', []))
    return conditioned


def _get_boundary_perms(iam, caller_type: str, name: str) -> set[str] | None:
    """
    Returns the allow set of the entity's PermissionsBoundary policy, or None if not set.
    If boundary exists, caller's effective permissions = perms ∩ boundary_perms.
    """
    try:
        if caller_type == 'iam_user':
            entity = iam.get_user(UserName=name)['User']
        else:
            entity = iam.get_role(RoleName=name)['Role']
        boundary_arn = entity.get('PermissionsBoundary', {}).get('PermissionsBoundaryArn')
        if not boundary_arn:
            return None
        return _extract_allows(_fetch_policy_doc(iam, boundary_arn))
    except ClientError:
        return None


def _fetch_policy_doc(iam, policy_arn: str) -> dict:
    try:
        meta = iam.get_policy(PolicyArn=policy_arn)['Policy']
        return iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=meta['DefaultVersionId'],
        )['PolicyVersion']['Document']
    except ClientError:
        return {}


def get_caller_permissions(session: boto3.Session, identity: dict) -> tuple[set[str], set[str]]:
    """
    Resolve effective Allow actions for the calling identity.
    Handles iam_user (inline + attached + group policies) and assumed_role (inline + attached).
    Applies PermissionsBoundary if one is set.

    Returns (all_allows, conditioned_subset):
      all_allows       — lowercased actions the caller can perform (post-boundary)
      conditioned_subset — subset of all_allows that have a Condition block attached
                           (may not work without satisfying the condition)
    """
    iam = session.client('iam')
    perms: set[str] = set()
    conditioned: set[str] = set()
    caller_type = identity.get('type', '')
    caller_arn = identity.get('arn', '')

    def _ingest(doc: dict):
        perms.update(_extract_allows(doc))
        conditioned.update(_extract_conditioned_allows(doc))

    def _add_inline_user(username: str):
        try:
            pager = iam.get_paginator('list_user_policies')
            for page in pager.paginate(UserName=username):
                for name in page['PolicyNames']:
                    try:
                        doc = iam.get_user_policy(UserName=username, PolicyName=name)['PolicyDocument']
                        _ingest(doc)
                    except ClientError:
                        pass
        except ClientError:
            pass

    def _add_attached_user(username: str):
        try:
            pager = iam.get_paginator('list_attached_user_policies')
            for page in pager.paginate(UserName=username):
                for p in page['AttachedPolicies']:
                    _ingest(_fetch_policy_doc(iam, p['PolicyArn']))
        except ClientError:
            pass

    def _add_inline_role(role_name: str):
        try:
            pager = iam.get_paginator('list_role_policies')
            for page in pager.paginate(RoleName=role_name):
                for name in page['PolicyNames']:
                    try:
                        doc = iam.get_role_policy(RoleName=role_name, PolicyName=name)['PolicyDocument']
                        _ingest(doc)
                    except ClientError:
                        pass
        except ClientError:
            pass

    def _add_attached_role(role_name: str) -> list[dict]:
        attached = []
        try:
            pager = iam.get_paginator('list_attached_role_policies')
            for page in pager.paginate(RoleName=role_name):
                for p in page['AttachedPolicies']:
                    _ingest(_fetch_policy_doc(iam, p['PolicyArn']))
                    attached.append({'PolicyName': p['PolicyName'], 'PolicyArn': p['PolicyArn']})
        except ClientError:
            pass
        return attached

    if caller_type == 'iam_user':
        username = caller_arn.split('/')[-1]
        _add_inline_user(username)
        _add_attached_user(username)
        try:
            pager = iam.get_paginator('list_groups_for_user')
            for page in pager.paginate(UserName=username):
                for group in page['Groups']:
                    gname = group['GroupName']
                    try:
                        gp = iam.get_paginator('list_group_policies')
                        for gpage in gp.paginate(GroupName=gname):
                            for pname in gpage['PolicyNames']:
                                try:
                                    doc = iam.get_group_policy(GroupName=gname, PolicyName=pname)['PolicyDocument']
                                    _ingest(doc)
                                except ClientError:
                                    pass
                    except ClientError:
                        pass
                    try:
                        gap = iam.get_paginator('list_attached_group_policies')
                        for gapage in gap.paginate(GroupName=gname):
                            for p in gapage['AttachedPolicies']:
                                _ingest(_fetch_policy_doc(iam, p['PolicyArn']))
                    except ClientError:
                        pass
        except ClientError:
            pass

    elif caller_type == 'assumed_role':
        # arn:aws:sts::account:assumed-role/role-name/session
        parts = caller_arn.split('/')
        if len(parts) >= 2:
            role_name = parts[1]
            _add_inline_role(role_name)
            _add_attached_role(role_name)

    # Apply PermissionsBoundary if one is set — hard cap on effective permissions
    entity_name = caller_arn.split('/')[-1]
    boundary = _get_boundary_perms(iam, caller_type, entity_name)
    if boundary is not None:
        perms &= boundary
        conditioned &= boundary

    return perms, conditioned


def enumerate_iam(session: boto3.Session) -> dict:
    iam = session.client('iam')
    results = {'users': [], 'roles': [], 'policies': [], 'errors': []}

    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            results['users'].extend(page['Users'])
    except ClientError as e:
        results['errors'].append(f"list_users: {e.response['Error']['Code']}")

    for user in results['users']:
        try:
            resp = iam.list_mfa_devices(UserName=user['UserName'])
            user['has_mfa'] = len(resp['MFADevices']) > 0
        except ClientError:
            user['has_mfa'] = None

    try:
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            results['roles'].extend(page['Roles'])
    except ClientError as e:
        results['errors'].append(f"list_roles: {e.response['Error']['Code']}")

    for role in results['roles']:
        try:
            pager = iam.get_paginator('list_attached_role_policies')
            role['attached_policies'] = []
            for page in pager.paginate(RoleName=role['RoleName']):
                role['attached_policies'].extend(page['AttachedPolicies'])
        except ClientError:
            role['attached_policies'] = []

    try:
        paginator = iam.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            results['policies'].extend(page['Policies'])
    except ClientError as e:
        results['errors'].append(f"list_policies: {e.response['Error']['Code']}")

    return results
