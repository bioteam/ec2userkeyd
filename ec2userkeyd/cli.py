# Functions related to command-line use
import os
import logging
import logging.handlers

import click

from ec2userkeyd import proxy, methods, config


logger = logging.getLogger(__name__)


def setup_logging():
    try:
        log_level = getattr(logging, config.general.log_level.upper())
    except AttributeError:
        raise Exception(f"Log level not recognized: {config.general.log_level}")
    root_logger = logging.getLogger('')
    root_logger.setLevel(log_level)

    # let's disable debugging boto logs
    if log_level == logging.DEBUG:
        for module in ['boto3', 'botocore', 'nose', 'urllib3']:
            logging.getLogger(module).setLevel(logging.WARNING)
    
    if config.general.log_console:
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s %(name)s:%(lineno)d %(message)s'))
        root_logger.addHandler(console)
    
    if config.general.log_syslog:
        syslog = logging.handlers.SysLogHandler(address='/dev/log')
        syslog.setFormatter(logging.Formatter(
            'ec2userkeyd[%(process)d]: [%(name)s:%(levelname)s]'
            ' %(message)s'))
        root_logger.addHandler(syslog)


@click.group()
@click.option('-f', '--config', 'cfgfile', metavar='FILE',
              default='/etc/ec2userkeyd.conf', help='Configuration file')
@click.option('-d', '--debug', is_flag=True, help='Enable debug output')
@click.option('-v', '--verbose', is_flag=True, help='Log to console')
def cli(cfgfile, debug, verbose):
    config.update(cfgfile)
    if verbose:
        config.general.log_level = 'INFO'
        config.general.log_console = True
    if debug:
        config.general.log_level = 'DEBUG'
        
    setup_logging()
        

@click.command(help="Run the credential serve daemon")
def daemon():
    # Set up iptables rules. Note that there is a brief race here
    # where credential requests may be rejected until the Flask app
    # starts up. There doesn't seem to be a good way to get this to
    # run after Flask starts...
    proxy.Iptables(config.general.daemon_port).activate()
    # Start the daemon
    os.environ['FLASK_ENV'] = 'active'
    proxy.app.run(port=config.general.daemon_port)
cli.add_command(daemon)

