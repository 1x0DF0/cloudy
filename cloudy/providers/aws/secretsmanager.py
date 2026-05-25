"""
AWS Secrets Manager enumeration.
"""

import boto3
from botocore.exceptions import ClientError


def enumerate_secrets(session: boto3.Session, region: str) -> dict:
    """
    Returns:
        secrets:  list of {name, arn, accessible, value_preview, region}
        errors:   list of str
    """
    client = session.client('secretsmanager', region_name=region)
    results: dict = {'secrets': [], 'errors': []}

    secret_list: list[dict] = []
    try:
        pager = client.get_paginator('list_secrets')
        for page in pager.paginate():
            secret_list.extend(page.get('SecretList', []))
    except ClientError as e:
        results['errors'].append(f"list_secrets/{region}: {e.response['Error']['Code']}")
        return results

    for secret in secret_list:
        entry: dict = {
            'name': secret['Name'],
            'arn': secret['ARN'],
            'accessible': False,
            'value_preview': None,
            'region': region,
        }
        try:
            resp = client.get_secret_value(SecretId=secret['ARN'])
            val = resp.get('SecretString') or '<binary>'
            entry['accessible'] = True
            entry['value_preview'] = val[:120] + '…' if len(val) > 120 else val
        except ClientError as e:
            code = e.response['Error']['Code']
            if code not in ('AccessDeniedException', 'AccessDenied', 'ResourceNotFoundException'):
                results['errors'].append(f"get_secret_value/{secret['Name']}: {code}")
        results['secrets'].append(entry)

    return results
