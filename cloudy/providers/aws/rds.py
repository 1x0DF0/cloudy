"""
AWS RDS enumeration: public snapshots (world-readable) and publicly accessible instances.
"""

import boto3
from botocore.exceptions import ClientError


def enumerate_rds(session: boto3.Session, region: str) -> dict:
    """
    Returns:
        public_snapshots: list of {id, arn, engine, size_gb, region}
        instances:        list of {id, engine, publicly_accessible, endpoint, region}
        errors:           list of str
    """
    client = session.client('rds', region_name=region)
    results: dict = {'public_snapshots': [], 'instances': [], 'errors': []}

    # Public snapshots — visible to any AWS account, free data
    try:
        pager = client.get_paginator('describe_db_snapshots')
        for page in pager.paginate(SnapshotType='public', IncludePublic=True):
            for snap in page.get('DBSnapshots', []):
                # Only flag snapshots owned by THIS account to avoid noise
                # (AWS has thousands of public AMI-style snapshots from managed services)
                if snap.get('MasterUsername'):  # own snapshots have this
                    results['public_snapshots'].append({
                        'id': snap['DBSnapshotIdentifier'],
                        'arn': snap.get('DBSnapshotArn', ''),
                        'engine': snap.get('Engine', ''),
                        'size_gb': snap.get('AllocatedStorage', 0),
                        'region': region,
                    })
    except ClientError as e:
        code = e.response['Error']['Code']
        if code not in ('AccessDenied', 'AccessDeniedException'):
            results['errors'].append(f"describe_db_snapshots/{region}: {code}")

    # Instances — flag PubliclyAccessible
    try:
        pager = client.get_paginator('describe_db_instances')
        for page in pager.paginate():
            for inst in page.get('DBInstances', []):
                if inst.get('PubliclyAccessible'):
                    endpoint = inst.get('Endpoint', {})
                    results['instances'].append({
                        'id': inst['DBInstanceIdentifier'],
                        'engine': inst.get('Engine', ''),
                        'publicly_accessible': True,
                        'endpoint': f"{endpoint.get('Address', '')}:{endpoint.get('Port', '')}",
                        'region': region,
                    })
    except ClientError as e:
        code = e.response['Error']['Code']
        if code not in ('AccessDenied', 'AccessDeniedException'):
            results['errors'].append(f"describe_db_instances/{region}: {code}")

    return results
