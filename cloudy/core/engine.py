import concurrent.futures
import boto3
from botocore.exceptions import ClientError

from providers.aws.identity import get_identity
from providers.aws.iam import enumerate_iam, get_caller_permissions
from providers.aws.ec2 import enumerate_ec2
from providers.aws.s3 import enumerate_s3
from providers.aws.ssm import enumerate_ssm
from providers.aws.lambda_ import enumerate_lambda
from providers.aws.secretsmanager import enumerate_secrets
from providers.aws.cloudformation import enumerate_cloudformation
from providers.aws.rds import enumerate_rds
from providers.aws.organizations import get_scp_restrictions, apply_scps


class ScanEngine:
    def __init__(self, profile: str | None = None, regions: list[str] | None = None, max_workers: int = 10):
        self.session = boto3.Session(profile_name=profile)
        self.max_workers = max_workers
        self._regions = regions

    def _get_regions(self) -> list[str]:
        if self._regions:
            return self._regions
        ec2 = self.session.client('ec2', region_name='us-east-1')
        try:
            resp = ec2.describe_regions(
                Filters=[{'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}]
            )
            return [r['RegionName'] for r in resp['Regions']]
        except ClientError:
            return ['us-east-1']

    def _scan_regions(self, func) -> dict:
        regions = self._get_regions()
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(func, self.session, r): r for r in regions}
            for future in concurrent.futures.as_completed(futures):
                region = futures[future]
                try:
                    results[region] = future.result()
                except Exception as e:
                    results[region] = {'error': str(e)}
        return results

    def run(self) -> dict:
        identity = get_identity(self.session)
        if 'error' in identity:
            return {'identity': identity, 'error': identity['error']}

        caller_perms, caller_conditioned = get_caller_permissions(self.session, identity)
        scps = get_scp_restrictions(self.session, identity.get('account_id', ''))
        effective_perms = apply_scps(caller_perms, scps)
        effective_conditioned = apply_scps(caller_conditioned, scps)
        iam_data = enumerate_iam(self.session)

        return {
            'identity': identity,
            'caller_permissions': effective_perms,
            'caller_conditioned': effective_conditioned,
            'scp_applied': scps is not None,
            'iam': iam_data,
            'ec2': self._scan_regions(enumerate_ec2),
            's3': enumerate_s3(self.session),
            'ssm': self._scan_regions(enumerate_ssm),
            'lambda': self._scan_regions(enumerate_lambda),
            'secrets': self._scan_regions(enumerate_secrets),
            'cloudformation': self._scan_regions(enumerate_cloudformation),
            'rds': self._scan_regions(enumerate_rds),
        }
