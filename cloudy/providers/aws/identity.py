import boto3
from botocore.exceptions import ClientError, NoCredentialsError

def get_identity(session: boto3.Session) -> dict:
    sts = session.client('sts')
    try:
        identity = sts.get_caller_identity()
        return {
            'account_id': identity['Account'],
            'user_id': identity['UserId'],
            'arn': identity['Arn'],
            'type': parse_principal_type(identity['Arn'])
        }
    except NoCredentialsError:
        return {'error': 'no_credentials'}
    except ClientError as e:
        return {'error': str(e)}

def parse_principal_type(arn: str) -> str:
    if 'assumed-role' in arn:
        return 'assumed_role'
    elif 'user' in arn:
        return 'iam_user'
    elif 'root' in arn:
        return 'root'
    return 'unknown'
