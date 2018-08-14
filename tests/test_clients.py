
import pytest
from moto import mock_iam

from ec2userkeyd import clients, utils


def test_current_role_arn(mocker):
    mocker.patch(
        'ec2userkeyd.clients.sts.get_caller_identity',
        return_value={'Arn': 'arn:aws:sts::123456789012:assumed-role/trl/joe'})
    assert clients.current_role_arn() == 'arn:aws:iam::123456789012:role/trl'


@pytest.fixture
def sim_iam():
    mock_iam_instance = mock_iam()
    mock_iam_instance.start()

    # Create a user and role with attached policies
    user = clients.iam_resource.create_user(UserName='joe')
    group = clients.iam_resource.create_group(GroupName='testgroup')

    group_policy = clients.iam_resource.create_policy(
        PolicyName='group-managed-policy',
        PolicyDocument=utils.make_iam_policy([{
            'Action': 'iam:CreatePolicyVersion', 'Resource': '*',
            'Effect': 'Allow'}])
    )
    group.attach_policy(PolicyArn=group_policy.arn)
    group.create_policy(
        PolicyName='group-policy',
        PolicyDocument=utils.make_iam_policy([{
            'Action': 'iam:PutGroupPolicy', 'Resource': '*',
            'Effect': 'Allow'}])
    )
    user.add_group(GroupName='testgroup')
    
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

    role = clients.iam_resource.create_role(
        RoleName='trl',
        AssumeRolePolicyDocument=utils.make_iam_policy([{
            'Effect': 'Allow', 'Principal': {'Service': ['ec2.amazonaws.com']},
            'Action': ['sts:AssumeRole']}])
    )

    role_policy = clients.iam_resource.create_policy(
        PolicyName='role-managed-policy',
        PolicyDocument=utils.make_iam_policy([{
            'Action': 'iam:ListPolicyVersions', 'Resource': '*',
            'Effect': 'Allow'}])
    )
    role.attach_policy(PolicyArn=role_policy.arn)
    role.Policy('role-policy').put(
        PolicyDocument=utils.make_iam_policy([{
            'Action': 'iam:PutRolePolicy', 'Resource': '*',
            'Effect': 'Allow'}])
    )
    
    yield

    mock_iam_instance.stop()

    
def test_get_iam_user_policy_statements(sim_iam):
    expected_statements = [
        {'Action': 'iam:CreatePolicyVersion', 'Resource': '*',
         'Effect': 'Allow'},
        {'Action': 'iam:PutGroupPolicy', 'Resource': '*', 'Effect': 'Allow'},
        {'Action': 'iam:CreatePolicy', 'Resource': '*', 'Effect': 'Allow'},
        {'Action': 'iam:PutUserPolicy', 'Resource': '*', 'Effect': 'Allow'},
    ]
    actual_statements = clients.get_iam_user_policy_statements('joe')
    assert len(actual_statements) == len(expected_statements)
    for statement in expected_statements:
        assert statement in actual_statements
