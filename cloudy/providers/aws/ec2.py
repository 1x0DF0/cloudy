import boto3
from botocore.exceptions import ClientError


def enumerate_ec2(session: boto3.Session, region: str) -> dict:
    ec2 = session.client('ec2', region_name=region)
    results = {'instances': [], 'security_groups': [], 'vpcs': [], 'subnets': [], 'errors': []}

    try:
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for inst in reservation['Instances']:
                    results['instances'].append({
                        'id': inst['InstanceId'],
                        'region': region,
                        'state': inst['State']['Name'],
                        'public_ip': inst.get('PublicIpAddress'),
                        'private_ip': inst.get('PrivateIpAddress'),
                        'iam_profile': inst.get('IamInstanceProfile', {}).get('Arn'),
                        'subnet_id': inst.get('SubnetId'),
                        'vpc_id': inst.get('VpcId'),
                        'security_groups': [sg['GroupId'] for sg in inst.get('SecurityGroups', [])],
                        'tags': {t['Key']: t['Value'] for t in inst.get('Tags', [])},
                    })
    except ClientError as e:
        results['errors'].append(f"describe_instances/{region}: {e.response['Error']['Code']}")

    try:
        paginator = ec2.get_paginator('describe_security_groups')
        for page in paginator.paginate():
            results['security_groups'].extend(page['SecurityGroups'])
    except ClientError as e:
        results['errors'].append(f"describe_security_groups/{region}: {e.response['Error']['Code']}")

    try:
        paginator = ec2.get_paginator('describe_vpcs')
        for page in paginator.paginate():
            results['vpcs'].extend(page['Vpcs'])
    except ClientError as e:
        results['errors'].append(f"describe_vpcs/{region}: {e.response['Error']['Code']}")

    try:
        paginator = ec2.get_paginator('describe_subnets')
        for page in paginator.paginate():
            results['subnets'].extend(page['Subnets'])
    except ClientError as e:
        results['errors'].append(f"describe_subnets/{region}: {e.response['Error']['Code']}")

    return results
