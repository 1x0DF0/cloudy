"""
AWS CloudFormation stack output enumeration.
Stack Outputs routinely expose RDS endpoints, API keys, connection strings in plaintext.
"""

import boto3
from botocore.exceptions import ClientError

_CRED_KEYWORDS = {
    'password', 'passwd', 'secret', 'token', 'apikey', 'api_key',
    'access_key', 'private_key', 'credential', 'auth', 'db_pass',
    'database', 'connection', 'private', 'key', 'cert', 'endpoint',
}


def _is_sensitive(key: str) -> bool:
    low = key.lower()
    return any(kw in low for kw in _CRED_KEYWORDS)


def enumerate_cloudformation(session: boto3.Session, region: str) -> dict:
    """
    Returns:
        stacks:  list of {name, status, outputs: [{key, value, sensitive}]}
        errors:  list of str
    """
    client = session.client('cloudformation', region_name=region)
    results: dict = {'stacks': [], 'errors': []}

    try:
        pager = client.get_paginator('describe_stacks')
        for page in pager.paginate():
            for stack in page.get('Stacks', []):
                outputs = []
                for out in stack.get('Outputs', []):
                    key = out.get('OutputKey', '')
                    val = out.get('OutputValue', '')
                    outputs.append({
                        'key': key,
                        'value': val,
                        'sensitive': _is_sensitive(key),
                    })
                results['stacks'].append({
                    'name': stack['StackName'],
                    'status': stack.get('StackStatus', ''),
                    'region': region,
                    'outputs': outputs,
                })
    except ClientError as e:
        results['errors'].append(f"describe_stacks/{region}: {e.response['Error']['Code']}")

    return results
