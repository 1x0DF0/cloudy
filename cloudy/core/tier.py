import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def detect_tier(session: boto3.Session) -> int:
    """
    0 = unauth / public surface only
    1 = read-only (basic describe)
    2 = power user (IAM reads visible)
    3 = admin (full IAM authorization details)
    """
    try:
        iam = session.client('iam')

        try:
            iam.get_account_authorization_details(Filter=['User'], MaxItems=1)
            return 3
        except ClientError:
            pass

        try:
            iam.list_users(MaxItems=1)
            return 2
        except ClientError:
            pass

        ec2 = session.client('ec2', region_name='us-east-1')
        try:
            ec2.describe_instances(MaxResults=5)
            return 1
        except ClientError:
            pass

        return 0
    except NoCredentialsError:
        return 0
