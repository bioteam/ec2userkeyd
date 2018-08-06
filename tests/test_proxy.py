import os

import pytest
import responses

from ec2userkeyd import proxy


###
### Flask testing


@pytest.fixture
def flask_client():
    client = proxy.app.test_client()
    yield client


@responses.activate
def test_catch_all_1(flask_client):
    responses.add(responses.GET, 'http://169.254.169.254/', body='latest\n')
    rv = flask_client.get('/')
    assert rv.status_code == 200


@responses.activate
def test_catch_all_2(flask_client):
    responses.add(responses.GET, 'http://169.254.169.254/latest/',
                  body='meta-data\n')
    rv = flask_client.get('/latest/')
    assert rv.status_code == 200


def test_role_data_no_methods(mocker, flask_client):
    mocker.patch('ec2userkeyd.utils.get_user_from_port', return_value='joe')
    mocker.patch.object(proxy, 'credential_methods', [])
    rv = flask_client.get('/latest/meta-data/iam/security-credentials/testrole')
    assert rv.status_code == 404


def test_role_data_one_method(mocker, flask_client):
    mocker.patch('ec2userkeyd.utils.get_user_from_port', return_value='joe')
    mock_method = mocker.Mock(spec=['get'])
    mock_method.get.configure_mock(return_value={'Code': 'Success'})
    mocker.patch.object(proxy, 'credential_methods', [mock_method])

    rv = flask_client.get('/latest/meta-data/iam/security-credentials/testrole')
    assert rv.status_code == 200
    assert rv.data == b'{"Code":"Success"}\n'
    
    
###
### iptables testing

def test_iptables_activate(mocker):
    mocker.patch('subprocess.check_call')
    mocker.patch('atexit.register')
    
    # Called as a normal user, we shouldn't try subprocess
    ipt = proxy.Iptables(808)
    if os.getuid() != 0:
        ipt.activate()
        assert proxy.subprocess.check_call.call_count == 0

    mocker.patch('os.getuid', return_value=0)
    ipt.activate()
    assert proxy.subprocess.check_call.call_count == len(ipt.rules)
    proxy.atexit.register.assert_called_once_with(ipt.deactivate)
    

def test_iptables_deactivate(mocker):
    mocker.patch('subprocess.check_call')

    ipt = proxy.Iptables(808)
    if os.getuid() != 0:
        ipt.deactivate()
        assert proxy.subprocess.check_call.call_count == 0

    mocker.patch('os.getuid', return_value=0)
    ipt.deactivate()
    assert proxy.subprocess.check_call.call_count == len(ipt.rules)
