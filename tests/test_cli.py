
import click
from click.testing import CliRunner

from ec2userkeyd.cli import cli
from ec2userkeyd import proxy


def test_daemon_start(mocker):
    # Don't let Flask actually start up here
    mocker.patch('ec2userkeyd.proxy.app.run')
    
    runner = CliRunner()
    result = runner.invoke(cli, ['daemon'])
    assert result.exit_code == 0
    assert proxy.credential_methods != []
