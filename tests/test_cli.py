import os

import click
from click.testing import CliRunner

from ec2userkeyd.cli import cli
from ec2userkeyd import proxy

from tests import mock_config


def test_daemon_start(mocker, mock_config):
    mock_config.update({
        'general': {'iptables': '/bin/true'}
    })
    # Don't let Flask actually start up here
    mocker.patch('ec2userkeyd.proxy.app.run')
    mocker.patch('atexit.register')
    
    runner = CliRunner()
    result = runner.invoke(cli, ['daemon'])
    assert result.exit_code == 0
    proxy.app.run.assert_called_once()
    if os.getuid() == 0:
        proxy.atexit.register.assert_called_once()
