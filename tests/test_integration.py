import sys
import time
#import inspect
import threading
import contextlib

import pytest
import requests
import responses
from moto import mock_iam, mock_sts
from click.testing import CliRunner

from tests import mock_config
from ec2userkeyd.cli import cli


@pytest.fixture
def sim_iam():
    mock_iam_instance = mock_iam()
    mock_iam_instance.start()
    mock_sts_instance = mock_sts()
    mock_sts_instance.start()
    
    yield

    mock_iam_instance.stop()
    mock_sts_instance.stop()


@contextlib.contextmanager
def daemon(mocker):
    mocker.patch('atexit.register')
    
    runner = CliRunner()
    thread = threading.Thread(target=(
        lambda: setattr(runner, 'result', runner.invoke(cli, ['daemon']))))
    thread.start()
    time.sleep(0.25)

    try:
        yield
    finally:
        # Shutdown the Werkzeug server with a crazy hack
        shutdown_sent = False
        for frame in sys._current_frames().values():
            while frame is not None:
                if 'srv' in frame.f_locals:
                    srvr = frame.f_locals['srv']
                    srvr.shutdown()
                    shutdown_sent = True
                    break
                frame = frame.f_back
            else:
                continue
            break
        if shutdown_sent:
            print("Waiting for server to stop...")
            thread.join()
        else:
            print("Unable to send shutdown signal!")
            
        if hasattr(runner, 'result'):
            print(runner.result.output)


@pytest.fixture
def mock_local_metadata():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.GET, 'http://169.254.169.254/', body='latest\n')
        rsps.add(
            responses.GET,
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/trl',
            body='''{
  "Code" : "Success",
  "LastUpdated" : "2018-08-14T20:34:41Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA3P5VSJAB4EXAMPLE",
  "SecretAccessKey" : "Po0pFXLfdWXMCbLSl3htCPxUi4Yoyc8WrEXAMPLE",
  "Token" : "FQoGZXIvYXdzEF4aDK2YJx0aZ5uSH6EGtyK3A7gM+P4bhPcIWXulrfgw6ZhmLeOiwPQA49zOhi8hKQb6yTjq3hulozNtCJnarGaSAN3bpuDiOosEEXAMPLEap36Ketnm96cCXqX3DKI+xxI6fjNvkPPrPabfZRASIIyDy7TSNV7cDcPeOCnbGNFe82EN5wHU80Z6EZYitVaWGiQPx5aHimI007J1yh/IYyWYbUjlFqKACQ43WJly158Cx/5EzA6bSz8/wuesFtEGBGnH6vmbY7U8vhXTM+I7E4R1+xfsCrTMBhiYokW/zCmHA0s+GDPHR7o1JLdFnP3mm+Dtxeb8cRW7AVEXAMPLE0I3v3DS46pGMxtbEijzglYWIp/tRVHJW5nP3kPoCAsk/dxAw5S+fyst2nQ3y4QCqZGHRH3+rJnfNaeU6r1x52ffgnmaX75XV1WNniHPJ87n/ZKxwHMcKLqE52VK+RdgrSiFWLCpqMGUKPJLTZDIUOpv/cOQn7U+7XO42nvIFn56Iui5jxOCh8k+GqxWF34QQMP/hVmQBgVKf0QGhrW8UggGw7oczhUSX2Zc3Lz8Zh1gBFAB1EECXglClrDJK9ktt4WeEBJw8+aE3ZAo2vnM2wU=",
  "Expiration" : "2018-08-15T02:36:59Z"
}''')
        rsps.add_passthru('http://localhost:5000')

        yield
    

# All tests here are integration tests
pytestmark = pytest.mark.integration


def test_integration_smoke(sim_iam, mock_local_metadata, mock_config, mocker):
    mock_config.update({
        'general': {'daemon_port': 5000, 'iptables': '/bin/true'}
    })
    with daemon(mocker):
        result = requests.get('http://localhost:5000/')
        assert result.text == 'latest\n'

    
def test_integration_instance_role(sim_iam, mock_local_metadata, mock_config,
                                   mocker):
    mock_config.update({
        'general': {'daemon_port': 5000,
                    'iptables': '/bin/true',
                    'credential_methods': ['InstanceRole']},
        'method_InstanceRole': {'deny_assumerole': False,
                                'deny_secretsmanager': False,
                                'fail_safe': False}
    })
    with daemon(mocker):
        result = requests.get(
            'http://localhost:5000/latest/meta-data/iam/security-credentials/trl')
        j = result.json()
        assert j['Code'] == 'Success'
        assert 'AccessKeyId' in j
        assert 'SecretAccessKey' in j
        assert 'Token' in j
