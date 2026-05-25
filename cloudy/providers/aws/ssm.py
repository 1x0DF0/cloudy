"""
AWS SSM enumeration: Parameter Store values + SendCommand-exposed instances.
"""

import boto3
from botocore.exceptions import ClientError

_CRED_KEYWORDS = {
    'password', 'passwd', 'secret', 'token', 'apikey', 'api_key',
    'access_key', 'private_key', 'credential', 'auth', 'db_pass',
    'database_url', 'connection_string', 'private', 'cert',
}


def _is_sensitive_name(name: str) -> bool:
    low = name.lower()
    return any(kw in low for kw in _CRED_KEYWORDS)


def enumerate_ssm(session: boto3.Session, region: str) -> dict:
    """
    Returns:
        parameters: list of {name, type, sensitive, value_preview, accessible}
        errors:     list of str
    """
    ssm = session.client('ssm', region_name=region)
    results: dict = {'parameters': [], 'errors': []}

    # First pass: describe all (names + types, no values)
    param_names: list[str] = []
    try:
        pager = ssm.get_paginator('describe_parameters')
        for page in pager.paginate():
            for p in page.get('Parameters', []):
                param_names.append(p['Name'])
                results['parameters'].append({
                    'name': p['Name'],
                    'type': p.get('Type', 'String'),
                    'sensitive': _is_sensitive_name(p['Name']) or p.get('Type') == 'SecureString',
                    'value_preview': None,
                    'accessible': False,
                    'region': region,
                })
    except ClientError as e:
        results['errors'].append(f"describe_parameters/{region}: {e.response['Error']['Code']}")
        return results

    if not param_names:
        return results

    # Build index for value backfill
    param_index = {p['name']: p for p in results['parameters']}

    # Second pass: bulk get values in batches of 10
    for i in range(0, len(param_names), 10):
        batch = param_names[i:i + 10]
        try:
            resp = ssm.get_parameters(Names=batch, WithDecryption=True)
            for p in resp.get('Parameters', []):
                entry = param_index.get(p['Name'])
                if entry:
                    val = p.get('Value', '')
                    entry['accessible'] = True
                    entry['value_preview'] = val[:120] + '…' if len(val) > 120 else val
        except ClientError as e:
            code = e.response['Error']['Code']
            if code not in ('AccessDeniedException', 'AccessDenied'):
                results['errors'].append(f"get_parameters/{region}: {code}")

    return results
