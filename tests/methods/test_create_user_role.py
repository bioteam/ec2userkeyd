import datetime

import pytest
from moto import mock_iam, mock_sts
from tests import mock_config

from ec2userkeyd import clients, utils
from ec2userkeyd.methods import create_user_role


@pytest.fixture(params=['no-role', 'role-empty', 'role-full', 'role-overfull'])
def sim_iam(request):
    mock_iam_instance = mock_iam()
    mock_iam_instance.start()
    mock_sts_instance = mock_sts()
    mock_sts_instance.start()

    # Create a user with attached policies
    user = clients.iam_resource.create_user(UserName='john')
    group = clients.iam_resource.create_group(GroupName='jgroup')

    group_policy = clients.iam_resource.create_policy(
        PolicyName='group-managed-policy',
        PolicyDocument=utils.make_iam_policy([
            {'Action': 'iam:CreatePolicyVersion', 'Resource': '*',
             'Effect': 'Allow'},
            {'Action': 'iam:ListPolicyVersions', 'Resource': '*',
             'Effect': 'Allow'}
        ])
    )
    group.attach_policy(PolicyArn=group_policy.arn)
    group.create_policy(
        PolicyName='group-policy',
        PolicyDocument=utils.make_iam_policy([{
            'Action': 'iam:PutGroupPolicy', 'Resource': '*',
            'Effect': 'Allow'}])
    )
    user.add_group(GroupName='jgroup')
    
    user_policy = clients.iam_resource.create_policy(
        PolicyName='user-managed-policy',
        PolicyDocument=utils.make_iam_policy([{
            'Action': 'iam:CreatePolicy', 'Resource': '*', 'Effect': 'Allow'}])
    )
    user.attach_policy(PolicyArn=user_policy.arn)
    user.create_policy(
        PolicyName='user-policy',
        PolicyDocument=utils.make_iam_policy([{
            'Action': 'iam:PutUserPolicy', 'Resource': '*', 'Effect': 'Allow'}])
    )       

    if request.param >= 'role-empty':
        role = clients.iam_resource.create_role(
            RoleName='u-john',
            AssumeRolePolicyDocument=utils.make_iam_policy([{
                'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                'Principal': {'AWS': 'arn:aws:iam::123456789012:role/*'}
            }])
        )

    if request.param >= 'role-full':
        role.attach_policy(PolicyArn=user_policy.arn)
        role.attach_policy(PolicyArn=group_policy.arn)

        role.Policy('user-policy').put(
            PolicyDocument=utils.make_iam_policy([{
                'Action': 'iam:PutUserPolicy', 'Resource': '*',
                'Effect': 'Allow'}])
        )
        role.Policy('group-policy').put(
            PolicyDocument=utils.make_iam_policy([{
                'Action': 'iam:PutGroupPolicy', 'Resource': '*',
                'Effect': 'Allow'}])
        )

    if request.param >= 'role-overfull':
        extra_policy = clients.iam_resource.create_policy(
            PolicyName='extra-managed-policy',
            PolicyDocument=utils.make_iam_policy([{
                'Action': 'ec2:*', 'Resource': '*', 'Effect': 'Deny'}])
        )
        role.attach_policy(PolicyArn=extra_policy.arn)
        role.Policy('extra-policy').put(
            PolicyDocument=utils.make_iam_policy([{
                'Action': 's3:*', 'Resource': '*', 'Effect': 'Deny'}])
        )
    
    yield request.param

    mock_sts_instance.stop()
    mock_iam_instance.stop()
    

def test_create_user_role(mock_config, sim_iam):
    mock_config.update({
        'method_CreateUserRole': {
            'role_name_pattern': 'u-{username}',
            'instance_role_linked': False
        }
    })

    try:
        original_role_statements = clients.get_iam_role_policy_statements(
            'arn:aws:iam::123456789012:role/u-john')
    except clients.iam.exceptions.NoSuchEntityException:
        original_role_statements = []

    s = create_user_role.CreateUserRole()
    r = s.get('john', 'trl')
    assert r['Code'] == 'Success'

    # make sure the role has changed (unless it ought not to have)
    role_statements = clients.get_iam_role_policy_statements(
        'arn:aws:iam::123456789012:role/u-john')
    if sim_iam == 'role-full':
        assert ({i['Action'] for i in original_role_statements}
                == {i['Action'] for i in role_statements})
    else:
        assert ({i['Action'] for i in original_role_statements}
                != {i['Action'] for i in role_statements})
        
    # make sure the role matches the user
    user_statements = clients.get_iam_user_policy_statements('john')
    assert ({i['Action'] for i in user_statements}
            == {i['Action'] for i in role_statements})

    # check the role assumerolepolicydocument
    role = clients.iam_resource.Role('u-john')
    assert role.assume_role_policy_document == {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow', 'Action': 'sts:AssumeRole',
            'Principal': {'AWS': 'arn:aws:iam::123456789012:role/*'}
        }]
    }


def test_create_user_role_no_user(mock_config, sim_iam):
    s = create_user_role.CreateUserRole()
    r = s.get('jack', 'trl')
    assert r is None
