# Functions related to command-line use

import click

from ec2userkeyd import proxy, methods, config


@click.group()
@click.option('-f', '--config', 'cfgfile', metavar='FILE',
              default='/etc/ec2userkeyd.conf', help='Configuration file')
@click.option('-d', '--debug', is_flag=True, help='Enable debug output')
def cli(cfgfile, debug):
    config.update(cfgfile)


@click.command(help="Run the credential serve daemon")
def daemon():
    # Instantiate credential methods
    proxy.credential_methods = [
        getattr(methods, method_name)()
        for method_name in config.general.credential_methods
    ]
    # Set up iptables rules. Note that there is a brief race here
    # where credential requests may be rejected until the Flask app
    # starts up. There doesn't seem to be a good way to get this to
    # run after Flask starts...
    proxy.Iptables(config.general.daemon_port).activate()
    # Start the daemon
    proxy.app.run()
cli.add_command(daemon)

