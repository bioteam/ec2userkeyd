
from ec2userkeyd import utils


SAMPLE_SS_OUT = b'''State         Recv-Q          Send-Q                    Local Address:Port                    Peer Address:Port
ESTAB         0               0                          172.31.17.83:50550                   72.44.80.173:22            timer:(keepalive,119min,0) uid:1000 ino:208438 sk:11 <->
'''

def test_get_user_from_port_success(mocker):
    mocker.patch('platform.system', return_value='Linux')
    mocker.patch('subprocess.check_output', return_value=SAMPLE_SS_OUT)
    mocker.patch('pwd.getpwuid', return_value=mocker.Mock(pw_name='joe'))
    u = utils.get_user_from_port(50550)
    utils.pwd.getpwuid.assert_called_with(1000)
    assert u == 'joe'


def test_get_user_from_port_fail_1(mocker):
    # here, ss fails to return useful output
    mocker.patch('platform.system', return_value='Linux')
    mocker.patch('subprocess.check_output', return_value=b'nope')
    u = utils.get_user_from_port(50550)
    assert u is None


def test_get_user_from_port_fail_2(mocker):
    # here, we got the UID but not the username
    mocker.patch('platform.system', return_value='Linux')
    mocker.patch('subprocess.check_output', return_value=SAMPLE_SS_OUT)
    mocker.patch('pwd.getpwuid', side_effect=KeyError)
    u = utils.get_user_from_port(50550)
    utils.pwd.getpwuid.assert_called_with(1000)
    assert u is None

