import json
import boto3
from botocore.exceptions import ClientError


def _is_public(block: dict | None, policy: str | None, acl: dict | None) -> bool:
    if block:
        cfg = block.get('PublicAccessBlockConfiguration', {})
        if all([cfg.get('BlockPublicAcls'), cfg.get('IgnorePublicAcls'),
                cfg.get('BlockPublicPolicy'), cfg.get('RestrictPublicBuckets')]):
            return False

    if policy:
        try:
            for stmt in json.loads(policy).get('Statement', []):
                if stmt.get('Effect') != 'Allow':
                    continue
                principal = stmt.get('Principal')
                if principal == '*':
                    return True
                if isinstance(principal, dict):
                    aws = principal.get('AWS', '')
                    if aws == '*' or (isinstance(aws, list) and '*' in aws):
                        return True
        except (json.JSONDecodeError, AttributeError):
            pass

    if acl:
        for grant in acl.get('Grants', []):
            uri = grant.get('Grantee', {}).get('URI', '')
            if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                return True

    return False


def enumerate_s3(session: boto3.Session) -> dict:
    s3 = session.client('s3')
    results = {'buckets': [], 'errors': []}

    try:
        buckets = s3.list_buckets().get('Buckets', [])
    except ClientError as e:
        results['errors'].append(f"list_buckets: {e.response['Error']['Code']}")
        return results

    for bucket in buckets:
        name = bucket['Name']
        entry = {
            'name': name,
            'region': None,
            'public_access_block': None,
            'policy': None,
            'acl': None,
            'is_public': False,
        }

        try:
            loc = s3.get_bucket_location(Bucket=name)
            entry['region'] = loc['LocationConstraint'] or 'us-east-1'
        except ClientError:
            pass

        try:
            entry['public_access_block'] = s3.get_public_access_block(Bucket=name)
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                results['errors'].append(f"get_public_access_block/{name}: {e.response['Error']['Code']}")

        try:
            entry['policy'] = s3.get_bucket_policy(Bucket=name)['Policy']
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                results['errors'].append(f"get_bucket_policy/{name}: {e.response['Error']['Code']}")

        try:
            entry['acl'] = s3.get_bucket_acl(Bucket=name)
        except ClientError as e:
            results['errors'].append(f"get_bucket_acl/{name}: {e.response['Error']['Code']}")

        entry['is_public'] = _is_public(entry['public_access_block'], entry['policy'], entry['acl'])
        results['buckets'].append(entry)

    return results
