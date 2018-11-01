import datetime

import pytest
import responses

from tests import mock_config
from ec2userkeyd import config
from ec2userkeyd.methods import instance_role


@responses.activate
def test_instance_role_straight(mocker, mock_config):
    responses.add(
        responses.GET,
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/default-role',
        body='{"Code": "Success", "AccessKeyId": "test-key"}\n'
    )
    mock_config.update({
        'method_InstanceRole': {
            'deny_assumerole': False,
            'deny_secretsmanager': False,
            'fail_safe': False
        }
    })
    mocker.patch('ec2userkeyd.clients.sts.assume_role')
    
    s = instance_role.InstanceRole()
    r = s.get('joe', 'default-role')
    assert not instance_role.clients.sts.assume_role.called
    assert r['AccessKeyId'] == 'test-key'


@responses.activate
def test_instance_role_deny_assumerole(mocker, mock_config):
    mock_config.update({
        'method_InstanceRole': {
            'deny_assumerole': True,
            'deny_secretsmanager': False,
            'fail_safe': False
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
            'Arn': 'arn:aws:sts::123456789012:assumed-role/trl/joe'
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

    s = instance_role.InstanceRole()
    r = s.get('joe', 'trl')
    assert r['Code'] == 'Success'
    assert r['AccessKeyId'] == 'ASIA4HDGHRJJEXAMPLE'
    assert instance_role.clients.sts.assume_role.call_args[1]['Policy']


@responses.activate
def test_instance_role_deny_secretsmanager(mocker, mock_config):
    mock_config.update({
        'method_InstanceRole': {
            'deny_assumerole': False,
            'deny_secretsmanager': True,
            'fail_safe': True
        }
    })
    mocker.patch('ec2userkeyd.clients.current_role_arn',
                 return_value='arn:aws:iam::123456789012:role/trl')
    # This time, we're going to simulate an AccessDenied ClientError
    def client_error(*args, **kwargs):
        raise instance_role.clients.sts.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied'}}, 'AssumeRole')
    mocker.patch('ec2userkeyd.clients.sts.assume_role',
                 side_effect=client_error)

    s = instance_role.InstanceRole()
    r = s.get('joe', 'trl')
    assert r is None
