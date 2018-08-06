
from ec2userkeyd import clients

def test_current_role_arn(mocker):
    mocker.patch('ec2userkeyd.clients.sts.get_caller_identity',
                 return_value={'Arn': 'arn:aws:iam::123456789012:role/trl'})
    assert clients.current_role_arn() == 'arn:aws:iam::123456789012:role/trl'
