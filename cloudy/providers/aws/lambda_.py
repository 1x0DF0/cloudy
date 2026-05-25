"""
AWS Lambda enumeration: function list, execution roles, environment variables.
"""

import boto3
from botocore.exceptions import ClientError

_CRED_KEYWORDS = {
    'password', 'passwd', 'secret', 'token', 'apikey', 'api_key',
    'access_key', 'private_key', 'credential', 'auth', 'db_pass',
    'database_url', 'connection_string', 'private', 'key', 'cert',
}


def _flag_env_vars(env: dict[str, str]) -> list[str]:
    """Return list of env var keys that look like credentials."""
    return [k for k in env if any(kw in k.lower() for kw in _CRED_KEYWORDS)]


def enumerate_lambda(session: boto3.Session, region: str) -> dict:
    """
    Returns:
        functions: list of {name, arn, role, env_vars, flagged_keys, region}
        errors:    list of str
    """
    client = session.client('lambda', region_name=region)
    results: dict = {'functions': [], 'errors': []}

    try:
        pager = client.get_paginator('list_functions')
        for page in pager.paginate():
            for fn in page.get('Functions', []):
                env = fn.get('Environment', {}).get('Variables', {})
                flagged = _flag_env_vars(env)
                results['functions'].append({
                    'name': fn['FunctionName'],
                    'arn': fn['FunctionArn'],
                    'role': fn.get('Role', ''),
                    'runtime': fn.get('Runtime', ''),
                    'env_vars': env,
                    'flagged_keys': flagged,
                    'region': region,
                })
    except ClientError as e:
        results['errors'].append(f"list_functions/{region}: {e.response['Error']['Code']}")

    return results
