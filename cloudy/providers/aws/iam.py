import boto3
from botocore.exceptions import ClientError


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

    try:
        paginator = iam.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            results['policies'].extend(page['Policies'])
    except ClientError as e:
        results['errors'].append(f"list_policies: {e.response['Error']['Code']}")

    return results
