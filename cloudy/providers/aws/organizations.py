"""
AWS Organizations SCP resolution.
Walk OU hierarchy from the account up to root, collect all SCPs, return
deny and allow sets so callers can intersect with IAM permissions.

AccessDenied on any organizations API = standalone account or no org:read perms.
In both cases we return None to signal "SCP unknown, proceed without filter."
"""

import json
import boto3
from botocore.exceptions import ClientError


def _extract_scp_sets(policy_doc: dict) -> tuple[set[str], set[str]]:
    """Parse an SCP document → (allow_actions, deny_actions), lowercased."""
    allows: set[str] = set()
    denies: set[str] = set()
    for stmt in policy_doc.get('Statement', []):
        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        actions = {a.lower() for a in actions}
        if stmt.get('Effect') == 'Allow':
            allows |= actions
        elif stmt.get('Effect') == 'Deny':
            denies |= actions
    return allows, denies


def get_scp_restrictions(session: boto3.Session, account_id: str) -> dict | None:
    """
    Returns {'allow': set[str], 'deny': set[str]} representing the effective SCP
    constraints on the account, or None if SCPs are inaccessible / account is standalone.

    Effective SCP allow = intersection of all allow sets up the OU hierarchy.
    Explicit SCP denies = union of all deny sets up the OU hierarchy.
    """
    org = session.client('organizations', region_name='us-east-1')

    try:
        org.describe_organization()
    except ClientError:
        return None  # standalone account or no orgs perms

    # Walk hierarchy: account → OUs → root
    target_ids = []
    try:
        target_ids.append(account_id)
        current = account_id
        while True:
            resp = org.list_parents(ChildId=current)
            parents = resp.get('Parents', [])
            if not parents:
                break
            parent = parents[0]
            target_ids.append(parent['Id'])
            if parent['Type'] == 'ROOT':
                break
            current = parent['Id']
    except ClientError:
        return None

    cumulative_allows: set[str] | None = None  # None = "not yet initialized"
    cumulative_denies: set[str] = set()

    for target_id in target_ids:
        try:
            paginator = org.get_paginator('list_policies_for_target')
            for page in paginator.paginate(TargetId=target_id, Filter='SERVICE_CONTROL_POLICY'):
                for policy_summary in page.get('Policies', []):
                    try:
                        detail = org.describe_policy(PolicyId=policy_summary['Id'])
                        doc = json.loads(detail['Policy']['Content'])
                        allows, denies = _extract_scp_sets(doc)
                        if cumulative_allows is None:
                            cumulative_allows = allows
                        else:
                            cumulative_allows &= allows  # intersection
                        cumulative_denies |= denies
                    except (ClientError, json.JSONDecodeError):
                        pass
        except ClientError:
            pass

    if cumulative_allows is None:
        return None

    return {'allow': cumulative_allows, 'deny': cumulative_denies}


def apply_scps(permissions: set[str], scps: dict | None) -> set[str]:
    """
    Intersect caller permissions with SCP constraints.
    If scps is None (unknown), return permissions unchanged.
    """
    if scps is None:
        return permissions
    # Deny overrides everything; allow constrains what is possible
    return (permissions & scps['allow']) - scps['deny']
