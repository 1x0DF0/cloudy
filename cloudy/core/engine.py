import concurrent.futures
import boto3
from botocore.exceptions import ClientError

from providers.aws.identity import get_identity
from providers.aws.iam import enumerate_iam
from providers.aws.ec2 import enumerate_ec2
from providers.aws.s3 import enumerate_s3


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

        return {
            'identity': identity,
            'iam': enumerate_iam(self.session),
            'ec2': self._scan_regions(enumerate_ec2),
            's3': enumerate_s3(self.session),
        }
