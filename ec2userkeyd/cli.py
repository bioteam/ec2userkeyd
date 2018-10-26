# Functions related to command-line use

import logging

import click

from ec2userkeyd import proxy, methods, config


logger = logging.getLogger(__name__)


def setup_logging():
    root_logger = logging.getLogger('')
    root_logger.setLevel(config.general.log_level)

    if config.general.log_console:
        console = logging.StreamHandler()
        root_logger.addHandler(console)
    
    if config.general.log_syslog and hasattr(logging, 'SysLogHandler'):
        syslog = logging.SysLogHandler()
        root_logger.addHandler(syslog)


@click.group()
@click.option('-f', '--config', 'cfgfile', metavar='FILE',
              default='/etc/ec2userkeyd.conf', help='Configuration file')
@click.option('-d', '--debug', is_flag=True, help='Enable debug output')
@click.option('-v', '--verbose', is_flag=True, help='Log to console')
def cli(cfgfile, debug, verbose):
    config.update(cfgfile)
    if verbose:
        config.general.log_level = logging.INFO
        config.general.log_console = True
    if debug:
        config.general.log_level = logging.DEBUG
        
    setup_logging()
        

@click.command(help="Run the credential serve daemon")
def daemon():
    # Set up iptables rules. Note that there is a brief race here
    # where credential requests may be rejected until the Flask app
    # starts up. There doesn't seem to be a good way to get this to
    # run after Flask starts...
    proxy.Iptables(config.general.daemon_port).activate()
    # Start the daemon
    proxy.app.run()
cli.add_command(daemon)

