import datetime

import responses

from tests import mock_config
from ec2userkeyd.methods import user_role


@responses.activate
def test_user_role_success(mocker, mock_config):
    mock_config.update({
        'method_UserRole': {
            'role_name_pattern': 'myuser-{username}'
        }
    })
    mocker.patch('ec2userkeyd.clients.sts.get_caller_identity',
                 return_value={'Account': '123456789012'})
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
    s = user_role.UserRole()
    r = s.get('joe', 'trl')
    assert r['Code'] == 'Success'
    assert r['AccessKeyId'] == 'ASIA4HDGHRJJEXAMPLE'
    user_role.clients.sts.assume_role.assert_called_with(
        RoleArn='arn:aws:iam::123456789012:role/myuser-joe',
        RoleSessionName='joe'
    )


@responses.activate
def test_user_role_failure(mocker, mock_config):
    mock_config.update({
        'method_UserRole': {
            'role_name_pattern': 'myuser-{username}'
        }
    })
    mocker.patch('ec2userkeyd.clients.sts.get_caller_identity',
                 return_value={'Account': '123456789012'})
    def client_error(*args, **kwargs):
        raise user_role.clients.sts.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied'}}, 'AssumeRole')
    mocker.patch('ec2userkeyd.clients.sts.assume_role',
                 side_effect=client_error)

    s = user_role.UserRole()
    r = s.get('joe', 'trl')
    assert r is None
    
