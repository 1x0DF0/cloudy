import json
from datetime import datetime, timezone

import networkx as nx


def _default(obj):
    if isinstance(obj, set):
        return sorted(obj, key=str)
    return str(obj)


def export_json(scan_data: dict, findings: list[dict], graph: nx.DiGraph, path: str) -> None:
    iam = scan_data.get('iam', {})
    ec2_all = scan_data.get('ec2', {})
    s3 = scan_data.get('s3', {})

    output = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'identity': scan_data.get('identity', {}),
        'scp_applied': scan_data.get('scp_applied', False),
        'summary': {
            'iam_users': len(iam.get('users', [])),
            'iam_roles': len(iam.get('roles', [])),
            'iam_policies': len(iam.get('policies', [])),
            'ec2_instances': sum(
                len(r.get('instances', [])) for r in ec2_all.values()
                if isinstance(r, dict) and 'error' not in r
            ),
            's3_buckets': len(s3.get('buckets', [])),
            's3_public': len([b for b in s3.get('buckets', []) if b.get('is_public')]),
            'lambda_functions': sum(
                len(r.get('functions', [])) for r in scan_data.get('lambda', {}).values()
                if isinstance(r, dict)
            ),
            'ssm_parameters': sum(
                len(r.get('parameters', [])) for r in scan_data.get('ssm', {}).values()
                if isinstance(r, dict)
            ),
            'secrets': sum(
                len(r.get('secrets', [])) for r in scan_data.get('secrets', {}).values()
                if isinstance(r, dict)
            ),
            'cfn_stacks': sum(
                len(r.get('stacks', [])) for r in scan_data.get('cloudformation', {}).values()
                if isinstance(r, dict)
            ),
            'rds_public_snapshots': sum(
                len(r.get('public_snapshots', [])) for r in scan_data.get('rds', {}).values()
                if isinstance(r, dict)
            ),
        },
        'findings': findings,
        'graph': {
            'nodes': [{'id': n, **a} for n, a in graph.nodes(data=True)],
            'edges': [{'source': u, 'target': v, **d} for u, v, d in graph.edges(data=True)],
        },
    }

    with open(path, 'w') as f:
        json.dump(output, f, indent=2, default=_default)
