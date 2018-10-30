import re
import datetime

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

    assert ':role/' in rolearn, f'{rolearn} is not a role arn'
    rolename = rolearn.split('/')[-1]
    role = iam_resource.Role(rolename)

    for policy in role.policies.all():
        statements.extend(policy.policy_document['Statement'])
    for policy in role.attached_policies.all():
        statements.extend(policy.default_version.document['Statement'])

    return statements


ASSUME_ROLE_CACHE = {}

def cached_assume_role(**kwargs):
    """Assume role, saving the result in a local cache.

    NOTE: This method will throw exceptions from sts.assume_role.

    """
    key = (kwargs['RoleArn'], kwargs['RoleSessionName'],
           hash(kwargs.get('Policy')))
    if key in ASSUME_ROLE_CACHE:
        # check if it's expiring - 48% of the time between request and
        # expiration
        now = datetime.datetime.now(datetime.timezone.utc)
        exp = ASSUME_ROLE_CACHE[key]['Credentials']['Expiration']
        req = ASSUME_ROLE_CACHE[key]['RequestedAt']
        if exp.tzinfo is None:
            exp = exp.astimezone(datetime.timezone.utc)
        expire_fraction = 1.0 - ((exp - now) / (exp - req))
        if expire_fraction > 0.45:
            del(ASSUME_ROLE_CACHE[key])        

    if key not in ASSUME_ROLE_CACHE:
        response = sts.assume_role(**kwargs)
        response['RequestedAt'] = datetime.datetime.now(datetime.timezone.utc)
        ASSUME_ROLE_CACHE[key] = response
    
    return ASSUME_ROLE_CACHE[key]
