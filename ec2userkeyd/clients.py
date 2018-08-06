
import boto3


sts = boto3.client('sts')
iam = boto3.client('iam')


def current_role_arn():
    """Returns the current role ARN.
    """
    return sts.get_caller_identity()['Arn']


def get_iam_user_policy_statements(username):
    """Given an IAM username, return all IAM statements applicable to that
    user.
    """
    attached_policies = []
    statements = []
    
    # Pull policies from groups first
    user_groups = iam.list_groups_for_user(UserName=username)
    #print(user_groups)
    for group in user_groups['Groups']:
        attached_group_policies = iam.list_attached_group_policies(
            GroupName=group['GroupName'])
        #print(attached_group_policies)
        for policy in attached_group_policies['AttachedPolicies']:
            attached_policies.append(policy['PolicyArn'])

        inline_group_policies = iam.list_group_policies(
            GroupName=group['GroupName'])
        #print(inline_group_policies)
        for policy_name in inline_group_policies['PolicyNames']:
            policy_document = iam.get_group_policy(
                GroupName=group['GroupName'],
                PolicyName=policy_name)
            #print(policy_document)
            doc = policy_document['PolicyDocument']
            statements.extend(doc['Statement'])

    # Now pull the user's policies
    attached_user_policies = iam.list_attached_user_policies(
        UserName=username)
    #print(attached_user_policies)
    for policy in attached_user_policies['AttachedPolicies']:
        attached_policies.append(policy['PolicyArn'])

    inline_user_policies = iam.list_user_policies(
        UserName=username)
    #print(inline_user_policies)
    for policy_name in inline_user_policies['PolicyNames']:
        policy_document = iam.get_user_policy(
            UserName=username, PolicyName=policy_name)
        #print(policy_document)
        doc = policy_document['PolicyDocument']
        statements.extend(doc['Statement'])

    # Finally, read all of the managed policies
    for policy_arn in attached_policies:
        policy_metadata = iam.get_policy(PolicyArn=policy_arn)
        #print(policy_metadata)
        policy_version = policy_metadata['Policy']['DefaultVersionId']
        #print(policy_version)
        policy_document = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy_version)
        #print(policy_document)
        doc = policy_document['PolicyVersion']['Document']
        statements.extend(doc['Statement'])

    return statements
