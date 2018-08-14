import datetime

import pytest
from moto import mock_iam
from tests import mock_config

from ec2userkeyd import clients, utils
from ec2userkeyd.methods import restricted_instance_role


@pytest.fixture
def sim_iam():
    mock_iam_instance = mock_iam()
    mock_iam_instance.start()

    # Create a user and role with attached policies
    user = clients.iam_resource.create_user(UserName='joe')
    group = clients.iam_resource.create_group(GroupName='testgroup')

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
        PolicyDocument=utils.make_iam_policy([
            {'Action': 'iam:ListPolicyVersions', 'Resource': '*',
             'Effect': 'Allow'},
            {'Action': 's3:*', 'Resource': '*', 'Effect': 'Deny'},
        ])
    )
    role.attach_policy(PolicyArn=role_policy.arn)
    role.Policy('role-policy').put(
        PolicyDocument=utils.make_iam_policy([{
            'Action': 'iam:PutRolePolicy', 'Resource': '*',
            'Effect': 'Allow'}])
    )

    yield

    mock_iam_instance.stop()


def test_compress_statements(mocker, sim_iam):
    mocker.patch('ec2userkeyd.clients.current_role_arn',
                 return_value='arn:aws:iam::123456789012:role/trl')
    
    s = restricted_instance_role.RestrictedInstanceRole()
    statements = s.compress_statements([
        {'Action': 'iam:GetRolePolicy', 'Resource': '*', 'Effect': 'Allow'},
        {'Action': 'iam:CreatePolicy', 'Resource': '*', 'Effect': 'Deny'},
        {'Action': 'iam:ListPolicyVersions', 'Resource': '*',
         'Effect': 'Allow'},
        {'Action': 's3:*', 'Resource': '*', 'Effect': 'Deny'},
    ])
    assert statements == [
        {'Action': 'iam:CreatePolicy', 'Resource': '*', 'Effect': 'Deny'},
        {'Action': 'iam:ListPolicyVersions', 'Resource': '*',
         'Effect': 'Allow'},
    ]


def test_restricted_instance_role_success(mocker, sim_iam, mock_config):
    mock_config.update({
        'method_RestrictedInstanceRole': {
            'compress_user_policy': True
        }
    })
    mocker.patch('ec2userkeyd.clients.current_role_arn',
                 return_value='arn:aws:iam::123456789012:role/trl')
    mocker.patch('ec2userkeyd.clients.sts.assume_role', return_value={
        'Credentials': {
            'AccessKeyId': 'ASIA4HDGHRJJEXAMPLE',
            'SecretAccessKey': 'hNOum9nRSVV5+B4CSz0ClYhqjBlSJmLLEXAMPLE',
            'SessionToken': 'FQoGZXIvYXdzEJv//////////wEaDPnAr+5A+Ilz2hh6+yL2AeP1EkyKMM94oaTnyNBcUi+oWkepESvp3EgX6mOb2hK+DTvZKa/SU6fTdiTkUER5j+vjGWxZiJBW1Qe6FJf/Fty6q2G1+exMVnZtp9XAWve0Xv9iQJX7TRTXWQct5Myj0A13MSBgT2mWJ5eGo1JUuNap+KD4ymA2FI4XcjR0K058ChrT6GgD4tdYU0BcoYuTPyPnKG6LIMBiSOF5rf9qhOouBFFa2RtgbFKDCbWPvs8l/B85LGmMEgEaRudoYzAZwl8HsI2VfIs48hSvNx6I+Rzeai1HGm8DOGG90jw9pET2PNFvm+c0ymv9tcUDf4IZgT1gIPuTHyjBhqLbBQ==',
            'Expiration': datetime.datetime(2018, 8, 6, 18, 20, 1)
        },
        'AssumedRoleUser': {
            'AssumedRoleId': 'AROAII6C6WQYWEXAMPLE:joe',
            'Arn': 'arn:aws:sts::123456789012:assumed-role/myuser-joe/joe'
        },
        'PackedPolicySize': 7,
        'ResponseMetadata': {
            'RequestId': 'f3d7e409-999c-11e8-a727-353315564573',
            'HTTPStatusCode': 200,
            'HTTPHeaders': {
                'x-amzn-requestid': 'f3d7e409-999c-11e8-a727-353315564573',
                'content-type': 'text/xml',
                'content-length': '1114',
                'date': 'Mon, 06 Aug 2018 17:20:01 GMT'
            },
            'RetryAttempts': 0
        }
    })

    s = restricted_instance_role.RestrictedInstanceRole()
    r = s.get('joe', 'trl')
    assert r is not None
    assert r['Code'] == 'Success'
    assert r['AccessKeyId'] == 'ASIA4HDGHRJJEXAMPLE'
    restricted_instance_role.clients.sts.assume_role.assert_called_with(
        RoleArn='arn:aws:iam::123456789012:role/trl',
        RoleSessionName='joe',
        Policy='{"Version": "2012-10-17", "Statement": [{"Action": "iam:ListPolicyVersions", "Resource": "*", "Effect": "Allow"}]}'
    )
    

def test_restricted_instance_role_failure_1(mocker, sim_iam, mock_config):
    mock_config.update({
        'method_RestrictedInstanceRole': {
            'compress_user_policy': True
        }
    })
    mocker.patch('ec2userkeyd.clients.current_role_arn',
                 return_value='arn:aws:iam::123456789012:role/trl')
    def client_error(*args, **kwargs):
        raise restricted_instance_role.clients.sts.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied'}}, 'AssumeRole')
    mocker.patch('ec2userkeyd.clients.sts.assume_role',
                 side_effect=client_error)

    s = restricted_instance_role.RestrictedInstanceRole()
    r = s.get('joe', 'trl')
    assert r is None

