import re

import boto3


sts = boto3.client('sts')
iam = boto3.client('iam')
iam_resource = boto3.resource('iam')

def current_role_arn():
    """Returns the current role ARN.
    """
    arn = sts.get_caller_identity()['Arn']
    if 'assumed-role' in arn:
        # strip the sts, assumed- and trailing RoleSessionName
        m = re.match('^.*:([0-9]*):assumed-role(/[^/]+)/.*$', arn)
        arn = 'arn:aws:iam::' + m.group(1) + ':role' + m.group(2)
    return arn


def get_iam_user_policy_statements(username):
    """Given an IAM username, return all IAM statements applicable to that
    user.

    """
    statements = []
    
    user = iam_resource.User(username)
    
    for group in user.groups.all():
        for policy in group.policies.all():
            statements.extend(policy.policy_document['Statement'])
        for policy in group.attached_policies.all():
            statements.extend(policy.default_version.document['Statement'])

    for policy in user.policies.all():
        statements.extend(policy.policy_document['Statement'])
    for policy in user.attached_policies.all():
        statements.extend(policy.default_version.document['Statement'])
    
    return statements


def get_iam_role_policy_statements(rolearn):
    """Given an IAM role ARN, return all IAM statements applicable to that
    role. 

    """
    statements = []

    assert ':role/' in rolearn, '{} is not a role arn'.format(rolearn)
    rolename = rolearn.split('/')[-1]
    role = iam_resource.Role(rolename)

    for policy in role.policies.all():
        statements.extend(policy.policy_document['Statement'])
    for policy in role.attached_policies.all():
        statements.extend(policy.default_version.document['Statement'])

    return statements
